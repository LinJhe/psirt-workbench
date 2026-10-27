"""Offline, conservative mail suggestions over verified local evidence.

No network, attachment execution, status-code guesses, or automatic acknowledgement.
Full safe text is indexed once per message; only excerpts are used in timelines.
"""
import hashlib
import re
from html.parser import HTMLParser

from .store import Conflict, Invalid, encoded, timestamp

RULE_VERSION = 'sf-mail-rules/1'
INDEX_VERSION = 'sf-mail-index/1'
CATEGORIES = {'vulnerability', 'inquiry', 'notification', 'other', 'unknown'}
ATTENTION = {'priority', 'normal', 'reference'}
ANSWERS = {'unchecked', 'unanswered', 'partial', 'answered', 'not_required'}
REPLY_FACTS = {'unknown', 'sent_human', 'automated', 'draft_or_failed', 'internal', 'not_found'}
REVIEW_FIELDS = {'reviewed_category', 'reviewed_summary', 'reviewed_attention',
                 'answer_assessment', 'reply_ids', 'answer_note', 'analysis_digest',
                 'review_version', 'reviewed_reply_fact', 'reply_note'}
LABELS = {'vulnerability': '漏洞通報與補件', 'inquiry': '案件追問與一般詢問',
          'notification': '安全與系統通知', 'other': '廣告與其他', 'unknown': '待分類'}
META_FIELDS = ('Status', 'LastModifiedDate', 'HasAttachment', 'IsExternallyVisible',
               'IsClientManaged', 'IsDeleted')
ATTACHMENT_FIELDS = ('Attachments', 'attachments', 'attachment_evidence', 'attachments_read_state')


def digest(value):
    return hashlib.sha256(encoded(value).encode()).hexdigest()


def _time(value):
    try:
        return timestamp(value)
    except (Invalid, ValueError, TypeError):
        return None


def safe_text(value):
    """Redact secrets/armored material without cutting quotations or long bodies."""
    text = str(value or '').replace('\r\n', '\n').replace('\r', '\n').replace('\x00', '')
    text = re.sub(r'-----BEGIN [^-\n]+-----.*?(?:-----END [^-\n]+-----|\Z)',
                  '[加密／金鑰區塊未讀取]', text, flags=re.S)
    text = re.sub(r'(?i)\bBearer\s+[\w.=/+-]+|\bodt_[\w-]{12,}', '[憑證省略]', text)
    text = re.sub(r'(?im)^.*(?:password|secret|api[_ -]?key|access[_ -]?token)\s*[:=]\s*\S+.*$',
                  '[敏感欄位省略]', text)
    text = re.sub(r'[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}', '[聯絡地址省略]', text)
    text = re.sub(r'(https?://[^\s?<>]+)\?[^\s<>]+', r'\1?[參數省略]', text)
    return text.strip()


class _TextHTML(HTMLParser):
    """Extract text only; attributes/URLs never enter output or cause I/O."""
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []
        self.blocked = []
        self.quoted = False

    def handle_starttag(self, tag, attrs):
        if tag in ('script', 'style', 'head', 'template', 'svg', 'iframe', 'object'):
            self.blocked.append(tag)
        if self.blocked:
            return
        if tag == 'blockquote':
            self.quoted = True
            self.parts.append('\n----- quoted content -----\n')
        if tag in ('br', 'p', 'div', 'li', 'tr', 'h1', 'h2', 'h3', 'pre'):
            self.parts.append('\n')

    def handle_endtag(self, tag):
        if self.blocked:
            if tag == self.blocked[-1]:
                self.blocked.pop()
            return
        if tag in ('p', 'div', 'li', 'tr', 'blockquote', 'pre'):
            self.parts.append('\n')

    def handle_data(self, data):
        if not self.blocked:
            self.parts.append(data)


def readable(message):
    text = message.get('TextBody')
    html = message.get('HtmlBody')
    flags = []
    html_state = 'not_fetched' if 'HtmlBody' not in message else 'empty'
    if isinstance(text, str) and text.strip():
        raw, body_state = text, 'text_available'
        if html:
            html_state = 'available_not_needed'
    elif isinstance(html, str) and html.strip():
        parser = _TextHTML()
        try:
            parser.feed(html)
            parser.close()
            raw = ''.join(parser.parts)
            body_state, html_state = 'html_text_available', 'converted_to_safe_text'
            flags.append('html_only')
            if parser.quoted:
                flags.append('quoted_content')
        except (ValueError, AssertionError):
            raw, body_state, html_state = '', 'unreadable', 'conversion_failed'
    else:
        raw = ''
        body_state = 'not_fetched' if 'TextBody' not in message else 'empty'
        flags.append('body_unavailable')
    if re.search(r'-----BEGIN PGP MESSAGE-----', raw):
        flags.append('encrypted_unread')
    text = safe_text(raw)
    fresh, quoted, signature = [], [], []
    destination = fresh
    for line in text.splitlines():
        if re.match(r'(?i)^\s*(?:on .+ wrote:|寄件者[:：]|from:|-----\s*(?:original message|quoted content)|begin forwarded message|轉寄郵件|轉發郵件)', line):
            destination = quoted
            flags.extend(('quoted_content', 'body_split_uncertain'))
        elif destination is fresh and re.match(r'(?i)^\s*(?:--\s*$|best regards\b|kind regards\b|regards[,，]?\s*$|sincerely\b|此致)', line):
            destination = signature
            flags.append('signature_removed')
        if destination is fresh and line.lstrip().startswith('>'):
            quoted.append(line)
            flags.append('quoted_content')
        else:
            destination.append(line)
    fresh_text = '\n'.join(fresh).strip()
    if not fresh_text or fresh_text == '[加密／金鑰區塊未讀取]':
        flags.append('new_body_unavailable')
    attachment_present = bool(message.get('HasAttachment') or any(message.get(k) for k in ATTACHMENT_FIELDS[:-1]))
    attachment_state = str(message.get('attachments_read_state') or ('unread' if attachment_present else 'unknown'))
    if attachment_present or re.search(r'(?i)\battach(?:ment|ed|ments)\b|附件', fresh_text):
        if attachment_state not in ('read', 'verified_text'):
            flags.append('attachment_unread')
    return {'text': text, 'analysis_text': fresh_text, 'body_read_state': body_state,
            'html_read_state': html_state, 'attachment_read_state': attachment_state,
            'flags': sorted(set(flags))}


def merge_index(index, capture, run_id):
    """Index safe SF text, not the full multi-source capture; latest observation wins."""
    from .inbox import identity, instance_of
    from psirt_ops.sf_messages import email_items
    source = capture['sources']['salesforce']
    instance = instance_of(capture)
    messages = email_items(source)
    if not instance:
        if messages:
            raise Invalid('SF 來源 instance 未取得，不能建立往返信件識別')
        return
    for position, message in messages:
        mid = message.get('Id')
        if not isinstance(mid, str) or not mid or len(mid) > 100:
            raise Invalid('SF EmailMessage ID 不合法')
        key = identity(instance, mid)
        observed = source.get('observed_at')
        old = index.get(key)
        if old and _time(observed) and _time(old.get('observed_at')) and _time(observed) < _time(old['observed_at']):
            continue
        content = readable(message)
        # Deliberate allowlist. Collector time/window, API attributes and run paths
        # do not invalidate content. Missing fields differ from fetched empty values.
        inputs = {name: message[name] for name in ('Id', 'ParentId', 'Incoming', 'MessageDate',
                  'Subject', 'TextBody', 'HtmlBody') + META_FIELDS + ATTACHMENT_FIELDS if name in message}
        index[key] = {'id': key, 'instance': instance, 'email_id': mid, 'case_id': message.get('ParentId'),
                      'incoming': message.get('Incoming'), 'message_date': message.get('MessageDate'),
                      'subject': safe_text(message.get('Subject'))[:500], **content,
                      'status': safe_text(message.get('Status'))[:100] if 'Status' in message else None,
                      'modified_at': message.get('LastModifiedDate'), 'observed_at': observed,
                      'content_digest': digest(inputs),
                      'evidence_ref': f'runs/{run_id}/capture.json#/sources/salesforce/emails/{position}',
                      'evidence_sha256': digest(message)}


def _context_id(message):
    # An absent ParentId must never join unrelated messages into one conversation.
    return 'sfcontext-' + digest([message['instance'], message.get('case_id') or message['email_id']])


def build_contexts(index):
    grouped = {}
    for message in index.values():
        grouped.setdefault(_context_id(message), []).append(message)
    contexts = {}
    for cid, messages in grouped.items():
        messages.sort(key=lambda m: (_time(m.get('message_date')) is None,
                                    _time(m.get('message_date')).isoformat() if _time(m.get('message_date')) else '', m['email_id']))
        timeline = []
        for message in messages:
            automatic = bool(re.search(r'(?i)automated response|automatic reply|auto.?reply|自動回覆|自動回復', message['analysis_text']))
            nature = '來信' if message.get('incoming') is True else '自動回覆文字線索；待覆核' if automatic else '對外／人工／寄送狀態待覆核'
            timeline.append({k: message.get(k) for k in ('email_id', 'incoming', 'message_date', 'subject', 'status', 'evidence_ref', 'flags')} |
                            {'excerpt': message['text'][:1800], 'reply_nature': nature, 'sending_state': 'unknown',
                             'body_read_state': message['body_read_state'], 'html_read_state': message['html_read_state'],
                             'attachment_read_state': message['attachment_read_state']})
        contexts[cid] = {'instance': messages[0]['instance'], 'case_id': messages[0].get('case_id'),
                         'coverage': 'OBSERVED_ONLY', 'timeline': timeline,
                         'limits': ['僅本機已觀測往返；未保證查全、未核對跨案寄信。',
                                    'Outgoing 與 Status 原值不證明已寄出、人工回覆或已回答。']}
    return contexts, grouped


def _suggest(message):
    text = message.get('analysis_text', '')
    subject = message.get('subject', '')
    flags = message.get('flags', [])
    inquiry = r'(?i)\b(?:bounty|reward|pgp|public key|permission|authorization|status update|any update|follow.?up|disclosure date)\b|獎金|獎勵|公鑰|測試許可|請問|進度|詢問|揭露安排'
    vulnerability = r'(?i)\b(?:vulnerabilit\w*|proof.of.concept|poc|cve-\d|sql injection|remote code execution|buffer overflow|retest)\b|漏洞|重現|複測|驗證結果|補充證據'
    notice = r'(?i)\b(?:notification|security advisory|quarantine|service outage|service alert|newsletter)\b|系統通知|安全公告|隔離信|服務異常'
    other = r'(?i)\b(?:unsubscribe|webinar|marketing|promotion|special offer)\b|行銷|促銷|廣告|研討會|活動邀請'
    if re.search(vulnerability, text):
        category = 'vulnerability'
    elif re.search(inquiry, text):
        category = 'inquiry'
    elif re.search(notice, text + '\n' + subject):
        category = 'notification'
    elif re.search(other, text + '\n' + subject):
        category = 'other'
    elif 'encrypted_unread' in flags or 'new_body_unavailable' in flags:
        category = 'unknown'
    elif re.search(inquiry, subject):
        category = 'inquiry'
    elif re.search(vulnerability, subject):
        category = 'vulnerability'
    else:
        category = 'unknown'
    attention, reason = _attention(text)
    visible = [line.strip() for line in text.splitlines() if line.strip() and not re.match(r'(?i)^(?:hi|hello|dear)\b', line.strip())]
    excerpt = next((line for line in visible if '?' in line or '？' in line), visible[0] if visible else '')
    summary = ('來信新正文節錄（待覆核）：' + excerpt[:240]) if excerpt else '缺少可讀的新正文，內容待人工確認'
    next_action = {'vulnerability': '核對本封提供的技術證據與問題，再決定承接及需補資訊',
                   'inquiry': '核對本封詢問與後續人工答覆；政策或許可須查明依據',
                   'notification': '檢視通知內容與可能被隔離的研究員信件，再決定處理',
                   'other': '確認是否為參考訊息；人工確認不需回覆後才完成',
                   'unknown': '先判讀可讀內容並確認分類；未讀資料不能當不存在'}[category]
    if 'encrypted_unread' in flags or 'attachment_unread' in flags:
        next_action = '先依既有授權讀取加密內容／附件；未讀取前不要求研究員重寄已有證據'
    return category, summary, attention, reason, next_action


def _attention(text):
    """Surface original clauses; a keyword is never an assertion that it happened."""
    pattern = re.compile(r'(?i)\b(?:actively exploited|being exploited|data (?:breach|leak)|public (?:poc|exploit)|imminent disclosure|disclos(?:e|ing) (?:tomorrow|today))\b|正在被利用|資料外洩|公開\s*PoC|即將公開|明天公開|今天公開')
    negated = []
    for sentence in re.split(r'(?<=[.!?。！？；;])\s+|\n+', text):
        # Do not let a negation about one clause suppress an independent positive cue.
        for clause in re.split(r'(?i)\b(?:but|however|and)\b|[,，;；]|但是|不過|然而|但', sentence):
            for cue in pattern.finditer(clause):
                before, after = clause[:cue.start()], clause[cue.end():]
                before = re.sub(r"(?i)\b(?:is|was|were|are|has|have|had|did|does|do|can|could|would|should)n['’]t\b", 'not', before)
                denied = bool(re.search(
                    r"(?i)(?:\b(?:not|never)\s+(?:(?:yet|currently|been|being|publicly|widely)\s+)*|"
                    r"\b(?:not|never)\s+(?:(?:yet|been)\s+)*(?:published?|released?|observed?|confirmed?|detected?|experienced?|found|seen)\s+(?:(?:any|a|an|the)\s+)?|"
                    r"\bno\s+(?:(?:evidence\s+of|known|confirmed)\s+)?|\bwithout\s+(?:any\s+)?|"
                    r"(?:尚未|並未|沒有|未|無)(?:發現|確認|偵測到|證據顯示)?\s*)$", before))
                denied = denied or bool(re.match(r'(?i)^\s+(?:has|have|was|is)\s+not\s+(?:been\s+)?(?:published|released|observed|confirmed|detected)\b', after))
                if not denied:
                    return 'priority', '急迫術語線索，需人工核對（原句；不代表已發生）：' + sentence.strip()
                negated.append(sentence.strip())
    if negated:
        return 'normal', '原句否定此急迫線索，仍保留一般待辦供人工核對：' + '；'.join(dict.fromkeys(negated))
    return 'normal', '尚待人工判讀；未依信齡或規則分類自動降為參考'


def annotate(rows, index):
    contexts, grouped = build_contexts(index)
    for row in rows:
        source = row['source']
        message = index.get(row['id'])
        if message is None:
            # Legacy ledger can remain readable if full source is unavailable; never
            # pass its display excerpt off as a complete analyzed message.
            message = {'id': row['id'], 'instance': source['instance'], 'email_id': source['email_id'],
                       'case_id': source.get('case_id'), 'message_date': source.get('message_date'),
                       'subject': source.get('subject', ''), 'analysis_text': '', 'text': '',
                       'flags': ['full_source_unavailable'], 'content_digest': None,
                       'evidence_ref': source.get('evidence_ref')}
        cid = _context_id(message)
        members = grouped.get(cid, [message])
        own_time = _time(message.get('message_date'))
        candidates = [m for m in members if m.get('incoming') is False and own_time and
                      _time(m.get('message_date')) and _time(m['message_date']) > own_time]
        candidate_ids = [m['email_id'] for m in candidates]
        input_digest = digest({'rule': RULE_VERSION, 'message': message['email_id'],
                               'context': cid, 'evidence': sorted((m['email_id'], m.get('content_digest')) for m in members)})
        p = (row.get('record') or {}).get('payload', {})
        current = p.get('review_version') == '1' and p.get('analysis_digest') == input_digest
        has_review = bool(p.get('analysis_digest') or p.get('review_version'))
        stale = bool(has_review and not current)
        category, summary, attention, reason, next_action = _suggest(message)
        effective_category = p.get('reviewed_category') if current and p.get('reviewed_category') in CATEGORIES else category
        effective_attention = p.get('reviewed_attention') if current and p.get('reviewed_attention') in ATTENTION else attention
        answer = p.get('answer_assessment', 'unchecked') if current else 'unchecked'
        if answer not in ANSWERS:
            answer = 'unchecked'
        fact = {'state': 'candidates' if candidates else 'unknown',
                'label': '有後續 Outgoing 候選；寄送及人工性質待確認' if candidates else '本機查核範圍未見後續 Outgoing 候選；不代表確定未回覆',
                'candidate_ids': candidate_ids}
        if current and p.get('reviewed_reply_fact') in REPLY_FACTS - {'unknown'}:
            selected = p['reviewed_reply_fact']
            labels = {'sent_human': '人工覆核：已寄出人工回信', 'automated': '人工覆核：自動回覆',
                      'draft_or_failed': '人工覆核：草稿／寄送失敗', 'internal': '人工覆核：內部訊息',
                      'not_found': '人工覆核：查核範圍未見回覆（非全信箱保證）'}
            fact.update(state='human_verified' if selected == 'sent_human' else selected, label=labels[selected])
        # Completing local handling does not answer the sender's remaining
        # questions. Recompute the queue from saved evidence without rewriting
        # the review or changing the classification/evidence digest.
        needs_attention = bool(row['state'] != 'done' or row.get('needs_recheck') or stale or
                               (answer != 'not_required' and (effective_category == 'unknown' or
                                answer in {'unchecked', 'unanswered', 'partial'})))
        row['triage'] = {'suggested_category': category, 'category': effective_category,
                         'suggested_summary': summary, 'summary': p.get('reviewed_summary') or summary if current else summary,
                         'body_excerpt': message.get('text','')[:1800],
                         'body_read_state': message.get('body_read_state','not_fetched'),
                         'html_read_state': message.get('html_read_state','not_fetched'),
                         'attachment_read_state': message.get('attachment_read_state','unknown'),
                         'suggested_next_action': next_action, 'attention': effective_attention,
                         'suggested_attention': attention, 'attention_reason': reason, 'reply_fact': fact,
                         'answer_assessment': answer, 'input_digest': input_digest, 'needs_recheck': stale,
                         'review_current': current, 'needs_attention': needs_attention,
                         'evidence_refs': list(dict.fromkeys(m.get('evidence_ref') for m in [message] + candidates if m.get('evidence_ref'))),
                         'context_id': cid, 'flags': list(message.get('flags', [])), 'reply_candidate_ids': candidate_ids}
        # Keep old state and revision history; an updated analysis only raises a flag.
        row['needs_recheck'] = bool(row.get('needs_recheck') or stale)
    return contexts


def validate_review(payload, row, inbox):
    """Validate new review intent after operation replay; no mutation or I/O."""
    if not any(name in payload for name in REVIEW_FIELDS):
        return  # Existing legacy status-only requests remain the service's policy.
    if payload.get('review_version') != '1':
        raise Invalid('郵件覆核版本不合法，請重新開啟目前頁面')
    triage = row.get('triage') or {}
    if payload.get('analysis_digest') != triage.get('input_digest') or not triage.get('input_digest'):
        raise Conflict('往返信件或分析規則已變更，請讀回後重新覆核')
    for field, allowed, default in (('reviewed_category', CATEGORIES, 'unknown'),
                                    ('reviewed_attention', ATTENTION, 'normal'),
                                    ('answer_assessment', ANSWERS, 'unchecked'),
                                    ('reviewed_reply_fact', REPLY_FACTS, 'unknown')):
        if payload.get(field, default) not in allowed:
            raise Invalid('郵件覆核選項不合法：' + field)
    if not isinstance(payload.get('reviewer'), str) or not payload['reviewer'].strip():
        raise Invalid('人工覆核須填覆核者')
    raw_ids = payload.get('reply_ids', '')
    if not isinstance(raw_ids, str) or len(raw_ids) > 6000:
        raise Invalid('回覆證據 ID 格式不合法')
    ids = [part.strip() for part in raw_ids.split(',') if part.strip()]
    if len(ids) != len(set(ids)) or len(ids) > 100:
        raise Invalid('回覆證據 ID 重複或過多')
    candidates = set(triage.get('reply_candidate_ids', []))
    if any(mid not in candidates for mid in ids):
        raise Invalid('回覆證據須是本封來信同案、同來源且日期較後的 Outgoing 候選')
    fact = payload.get('reviewed_reply_fact', 'unknown')
    answer = payload.get('answer_assessment', 'unchecked')
    if fact != 'unknown' and not str(payload.get('reply_note', '')).strip():
        raise Invalid('寄送事實覆核須記錄依據')
    if fact in {'sent_human', 'automated', 'draft_or_failed', 'internal'} and not ids:
        raise Invalid('寄送事實覆核須選擇回覆證據 ID')
    if fact == 'not_found' and ids:
        raise Invalid('未見回覆不能同時選擇回覆證據')
    if answer in {'answered', 'partial'} and (fact != 'sent_human' or not ids):
        raise Invalid('已回答／部分回答須先人工確認已寄出人工回覆及證據')
    if answer != 'unchecked' and not str(payload.get('answer_note', '')).strip():
        raise Invalid('問題回答覆核須記錄對照或不需回覆理由')
