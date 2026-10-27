"""Pure dashboard acceptance: synthetic records, no services or API access."""
import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from psirt_casework.dashboard import build
from psirt_casework.projection import deadline
from psirt_casework.store import timestamp

ASOF = '2026-10-22T12:00:00+08:00'
PAST = '2026-10-21T09:00:00+08:00'
EXIT = '2026-10-21T11:00:00+08:00'
FUTURE = '2026-10-23T09:00:00+08:00'


def row(key, stage='unknown', category='indeterminate', **changes):
    return {'id': key, 'stage': stage, 'entered_at': PAST if stage != 'unknown' else None,
            'jira_status_category': category, 'jira_status': 'In Progress', 'stage_visits': [],
            'dates': {}, 'blocker': None, 'worklogs': [], 'waits': [], 'deliveries': [], **changes}


def projection(rows=(), complete=True, **changes):
    return {'as_of': ASOF, 'source': {'status': 'SUCCESS' if complete else 'PARTIAL',
                                     'complete': complete, 'historical': False},
            'counts': {'total': len(rows) if complete else None}, 'cases': list(rows), **changes}


def record(kind, key, payload, version=1):
    return {'kind': kind, 'id': key, 'version': version, 'payload': payload}


def visit(key, stage, entered=PAST, exited=EXIT, **changes):
    return {'id': key, 'stage': stage, 'confirmation': 'confirmed', 'entered_at': entered,
            'exited_at': exited, 'entry_evidence': 'fixture://entry', 'exit_evidence': 'fixture://exit',
            'reviewer': 'DEMO reviewer', 'event': 'transition', **changes}


def due(kind='commitment', at=PAST, **changes):
    basis = {'at': at, 'confirmation': 'confirmed', 'evidence': 'fixture://agreement',
             'confirmed_by': 'DEMO reviewer'}
    if kind == 'remediation':
        basis.update(basis_version='DEMO policy', trigger_event='DEMO event', scope='DEMO scope')
    basis.update(changes)
    return deadline(basis, kind, timestamp(ASOF))


def delivery(key, cases, **changes):
    return record('delivery', key, {'case_ids': cases, 'title': 'Synthetic report', 'received_at': PAST,
                  'outcome': 'Report received; no remediation claim', 'evidence': 'fixture://report',
                  'reviewer': 'DEMO reviewer', 'acceptance': 'pending', **changes})


def work(key, cases, minutes=30, **changes):
    return record('worklog', key, {'case_ids': cases, 'work_date': '2026-10-21', 'minutes': minutes,
                  'measurement': 'measured', 'evidence': 'fixture://work', **changes})


def nodes(dashboard, key):
    return {node['key']: node for node in dashboard['cases'][key]['timeline']}


class DashboardTests(unittest.TestCase):
    def test_metrics_are_clickable_observed_sets_and_overlap_is_explicit(self):
        waiting = record('wait', 'waiting', {'case_id': 'DEMO-A', 'start': PAST, 'evidence': 'fixture://wait'})
        data = projection([
            row('DEMO-A', 'analysis', waits=[waiting], dates={'commitment': due()}),
            row('DEMO-B', category='done'), row('DEMO-C', 'verification', category='done'),
            row('DEMO-D', dates={'followup': due('followup')}),
        ])
        result = build(data)
        expected = {'total': 4, 'active': 1, 'waiting': 1, 'overdue': 1, 'jira_done': 2, 'stage_unknown': 2}
        for key, count in expected.items():
            with self.subTest(metric=key):
                metric = result['metrics'][key]
                self.assertEqual(metric['value'], count)
                self.assertEqual(metric['observed_count'], count)
                self.assertEqual(len(set(metric['case_ids'])), count)
                self.assertTrue(set(metric['case_ids']) <= set(result['cases']))
        self.assertEqual(result['metrics']['active']['case_ids'], result['metrics']['waiting']['case_ids'])
        self.assertEqual(result['followup_due']['case_ids'], ['DEMO-D'])
        self.assertEqual(result['cases']['DEMO-A']['tone'], 'danger')
        self.assertIn('可重疊', ' '.join(result['limits']))

    def test_partial_failed_missing_and_explicit_unknown_never_become_zero_totals(self):
        inputs = [None, projection([], complete=False),
                  projection([row('DEMO-A')], source={'status': 'FAILED', 'complete': False, 'historical': True}),
                  projection([], counts={'total': None}),
                  projection([], source={'status': 'SUCCESS', 'complete': None})]
        for data in inputs:
            with self.subTest(data=data):
                result = build(data)
                self.assertFalse(result['scope']['complete'])
                self.assertTrue(all(m['value'] is None for m in result['metrics'].values()))
                self.assertIsNone(result['followup_due']['value'])
                self.assertTrue(all(stage['count'] is None for stage in result['stages']))
                self.assertEqual(result['metrics']['total']['observed_count'], len((data or {}).get('cases', [])))
                self.assertIsNone(result['work']['actual_minutes'])
        self.assertEqual(build(projection([]))['metrics']['total']['value'], 0)

    def test_only_source_category_done_counts_and_never_implies_repair_or_stage_completion(self):
        data = projection([row('DEMO-A', 'closure', jira_status='Closed', category=None),
                           row('DEMO-B', category='done', jira_status='Custom label')])
        result = build(data)
        self.assertEqual(result['metrics']['jira_done']['case_ids'], ['DEMO-B'])
        self.assertEqual(result['metrics']['active']['case_ids'], ['DEMO-A'])
        self.assertEqual(nodes(result, 'DEMO-A')['closure']['state'], 'current')
        self.assertTrue(all(node['state'] == 'unknown' for node in result['cases']['DEMO-B']['timeline']))
        self.assertNotIn('percent', result['cases']['DEMO-A'])
        self.assertNotIn('fixed', result['metrics'])
        self.assertIn('不等於修補完成、確認受影響', ' '.join(result['limits']))
        self.assertIn('非完整歷史', result['scope']['label'])

    def test_later_current_stage_does_not_complete_earlier_nodes(self):
        result = build(projection([row('DEMO-A', 'verification')]))
        timeline = nodes(result, 'DEMO-A')
        self.assertEqual(timeline['verification']['state'], 'current')
        self.assertEqual(timeline['analysis']['state'], 'unknown')
        self.assertEqual(timeline['intake']['state'], 'unknown')
        self.assertEqual(sum(node['state'] == 'completed' for node in timeline.values()), 0)

    def test_completion_requires_confirmation_both_evidence_reviewer_and_elapsed_times(self):
        visits = [visit('good', 'intake'), visit('pending', 'handoff', confirmation='pending'),
                  visit('no-exit-evidence', 'analysis', exit_evidence=''),
                  visit('no-reviewer', 'planning', reviewer=''),
                  visit('future-exit', 'development', exited=FUTURE),
                  visit('future-entry', 'verification', entered=FUTURE, exited=FUTURE),
                  visit('backwards', 'release', entered=EXIT, exited=PAST),
                  visit('no-entry-evidence', 'closure', entry_evidence='')]
        result = build(projection([row('DEMO-A', stage_visits=visits)]))
        self.assertEqual(nodes(result, 'DEMO-A')['intake']['state'], 'completed')
        self.assertEqual([key for key, node in nodes(result, 'DEMO-A').items() if node['state'] == 'completed'], ['intake'])

    def test_same_stage_reentry_and_cross_stage_return_override_old_completion(self):
        for visits in ([visit('analysis-1', 'analysis'), visit('analysis-2', 'analysis', exited=None, event='reentry')],
                       [visit('analysis-1', 'analysis'), visit('verify-1', 'verification'),
                        visit('analysis-2', 'analysis', exited=None)]):
            with self.subTest(visits=visits):
                data = projection([row('DEMO-A', 'analysis', stage_visits=visits)])
                original = copy.deepcopy(data)
                result = build(data)
                self.assertEqual(nodes(result, 'DEMO-A')['analysis']['state'], 'current')
                self.assertIn('重新進入', nodes(result, 'DEMO-A')['analysis']['note'])
                self.assertEqual(nodes(result, 'DEMO-A')['analysis']['visits'], ['analysis-1', 'analysis-2'])
                self.assertEqual(data, original)
        self.assertEqual(nodes(result, 'DEMO-A')['verification']['state'], 'completed')

    def test_future_entry_and_pending_history_cannot_create_current_progress(self):
        future = row('DEMO-FUTURE', 'analysis', entered_at=FUTURE,
                     stage_visits=[visit('future', 'analysis', entered=FUTURE, exited=None, current=True)])
        pending = row('DEMO-PENDING', stage_visits=[visit('pending', 'verification', confirmation='pending',
                                                       current=True, duration_minutes=120)])
        result = build(projection([future, pending]))
        self.assertEqual(result['metrics']['active']['value'], 0)
        self.assertEqual(result['metrics']['stage_unknown']['value'], 2)
        self.assertTrue(all(node['state'] == 'unknown' for case in result['cases'].values() for node in case['timeline']))

    def test_current_stage_without_entry_time_remains_confirmed_without_inventing_elapsed_history(self):
        result = build(projection([row('DEMO-A', 'analysis', entered_at=None)]))
        self.assertEqual(nodes(result, 'DEMO-A')['analysis']['state'], 'current')
        self.assertEqual(result['metrics']['active']['value'], 1)

    def test_waiting_uses_open_evidenced_wait_or_nonplaceholder_confirmed_blocker(self):
        rows = [row('DEMO-' + str(index), blocker=value) for index, value in enumerate(
            (None, '', '無', 'None', ' n/a ', 'NONE.', '無。', '-', '暫無'))]
        rows.append(row('DEMO-BLOCKED', blocker='無法重現，等待指定版本'))
        for key, start, end, evidence in [('OPEN', PAST, None, 'fixture://wait'),
                                           ('FUTURE', FUTURE, None, 'fixture://wait'),
                                           ('ENDED', PAST, EXIT, 'fixture://wait'),
                                           ('UNPROVEN', PAST, None, '')]:
            wait = record('wait', key, {'case_id': key, 'start': start, 'end': end, 'evidence': evidence})
            rows.append(row(key, waits=[wait]))
        result = build(projection(rows))
        self.assertEqual(result['metrics']['waiting']['case_ids'], ['DEMO-BLOCKED', 'OPEN'])

    def test_wait_end_is_evaluated_asof_and_invalid_end_does_not_establish_completion(self):
        rows = []
        for key, start, end, evidence in [
                ('FUTURE-END', PAST, FUTURE, 'fixture://wait'),
                ('INVALID-END', PAST, 'not-a-time', 'fixture://wait'),
                ('BACKWARDS-END', EXIT, PAST, 'fixture://wait'),
                ('ENDED-NOW', PAST, ASOF, 'fixture://wait'),
                ('ENDED-BEFORE', PAST, EXIT, 'fixture://wait'),
                ('NOT-STARTED', FUTURE, None, 'fixture://wait'),
                ('UNPROVEN-FUTURE-END', PAST, FUTURE, '')]:
            wait = record('wait', key, {'case_id': key, 'start': start, 'end': end, 'evidence': evidence})
            rows.append(row(key, waits=[wait]))
        expected = ['BACKWARDS-END', 'FUTURE-END', 'INVALID-END']
        result = build(projection(rows))
        self.assertEqual(result['metrics']['waiting']['case_ids'], expected)
        self.assertEqual(result['metrics']['waiting']['value'], 3)
        incomplete = build(projection(rows, complete=False))
        self.assertIsNone(incomplete['metrics']['waiting']['value'])
        self.assertEqual(incomplete['metrics']['waiting']['observed_count'], 3)
        self.assertEqual(incomplete['metrics']['waiting']['case_ids'], expected)

    def test_overdue_is_confirmed_commitment_or_remediation_not_followup_or_conflict(self):
        conflict = due(); conflict['state'] = 'UNKNOWN'
        future = due(at=FUTURE); future['state'] = 'COMMITMENT_OVERDUE'
        incomplete_remediation = due('remediation'); incomplete_remediation['basis']['scope'] = ''
        data = projection([
            row('DEMO-BOTH', dates={'commitment': due(), 'remediation': due('remediation')}),
            row('DEMO-FOLLOWUP', dates={'followup': due('followup')}),
            row('DEMO-PENDING', dates={'commitment': due(confirmation='pending')}),
            row('DEMO-CONFLICT', dates={'commitment': conflict}),
            row('DEMO-FUTURE', dates={'commitment': future}),
            row('DEMO-NO-SCOPE', dates={'remediation': incomplete_remediation}),
            row('DEMO-DONE-LATE', dates={'commitment': due(completed_at=EXIT, completion_evidence='fixture://done')}),
        ])
        result = build(data)
        self.assertEqual(result['metrics']['overdue']['case_ids'], ['DEMO-BOTH'])
        self.assertEqual(result['followup_due']['case_ids'], ['DEMO-FOLLOWUP'])

    def test_shared_deliveries_are_unique_and_acceptance_uses_evidence_and_asof(self):
        accepted = delivery('shared', ['DEMO-A', 'DEMO-B'], acceptance='accepted',
                            accepted_at=EXIT, acceptance_evidence='fixture://accept')
        future_accept = delivery('pending', ['DEMO-A'], acceptance='accepted',
                                 accepted_at=FUTURE, acceptance_evidence='fixture://future')
        future_receive = delivery('future', ['DEMO-A'], received_at=FUTURE)
        rows = [row('DEMO-A', deliveries=[accepted, future_accept, future_receive]),
                row('DEMO-B', deliveries=[copy.deepcopy(accepted)])]
        result = build(projection(rows, deliveries=[accepted, copy.deepcopy(accepted), future_accept, future_receive]))
        self.assertEqual(result['deliveries']['received'], 2)
        self.assertEqual(result['deliveries']['accepted'], 1)
        self.assertEqual(result['deliveries']['pending'], 1)
        self.assertEqual(result['deliveries']['percent'], 50.0)
        self.assertEqual(result['cases']['DEMO-A']['deliveries']['percent'], 50.0)
        self.assertEqual(result['cases']['DEMO-B']['deliveries']['percent'], 100.0)
        self.assertEqual(result['work']['received_count'], 2)
        self.assertEqual(result['work']['accepted_count'], 1)
        self.assertEqual(result['metrics']['jira_done']['value'], 0)

    def test_no_received_delivery_is_unknown_percent_and_unproven_acceptance_is_pending(self):
        self.assertIsNone(build(projection([row('DEMO-A')]))['cases']['DEMO-A']['deliveries']['percent'])
        unproven = delivery('one', ['DEMO-A'], acceptance='accepted', accepted_at=EXIT, acceptance_evidence='')
        result = build(projection([row('DEMO-A', deliveries=[unproven])]))
        self.assertEqual(result['deliveries']['received'], 1)
        self.assertEqual(result['deliveries']['accepted'], 0)
        self.assertEqual(result['deliveries']['percent'], 0.0)

    def test_global_work_is_unique_includes_unbound_and_excludes_estimates_future(self):
        shared = work('shared', ['DEMO-A', 'DEMO-B'])
        unbound = work('general', [], minutes=20)
        estimate = work('estimate', ['DEMO-A'], minutes=100, measurement='estimated')
        future = work('future', ['DEMO-A'], work_date='2026-10-23')
        future_end = work('future-end', ['DEMO-A'], start=PAST, end=FUTURE)
        rows = [row('DEMO-A', worklogs=[shared, estimate, future, future_end]), row('DEMO-B', worklogs=[shared])]
        result = build(projection(rows, worklogs=[shared, copy.deepcopy(shared), unbound, estimate, future, future_end]))
        self.assertEqual(result['work']['actual_minutes'], 50)
        self.assertEqual(result['work']['record_count'], 3)
        self.assertEqual(result['work']['measured_record_count'], 2)
        self.assertEqual(result['work']['shared_record_ids'], ['shared'])
        self.assertEqual(result['cases']['DEMO-A']['actual_minutes'], 30)
        self.assertEqual(result['cases']['DEMO-B']['actual_minutes'], 30)

    def test_no_measured_work_does_not_infer_zero_or_personal_hours_from_assignee(self):
        for records in ([], [work('estimate', ['DEMO-A'], measurement='estimated')]):
            result = build(projection([row('DEMO-A', assignee='DEMO Vance', actual_minutes=9999, worklogs=records)]))
            self.assertIsNone(result['work']['actual_minutes'])
            self.assertIsNone(result['cases']['DEMO-A']['actual_minutes'])

    def test_duplicate_ids_and_corrected_record_versions_do_not_inflate_counts(self):
        old = work('same', ['DEMO-A'], minutes=10)
        new = work('same', ['DEMO-A'], minutes=25); new['version'] = 2
        data = projection([row('DEMO-A'), row('DEMO-A')], worklogs=[new, old, copy.deepcopy(new)])
        result = build(data)
        self.assertEqual(result['metrics']['total']['value'], 1)
        self.assertEqual(result['work']['actual_minutes'], 25)
        self.assertEqual(result['work']['record_count'], 1)

    def test_pure_repeated_build_keeps_projection_and_history_unchanged(self):
        data = projection([row('DEMO-A', 'analysis', stage_visits=[visit('closed', 'intake')],
                               worklogs=[work('one', ['DEMO-A'])], deliveries=[delivery('one', ['DEMO-A'])])])
        original = copy.deepcopy(data)
        first = build(data)
        self.assertEqual(first, build(data))
        self.assertEqual(original, data)
        first['cases']['DEMO-A']['timeline'][0]['visits'].append('caller-mutation')
        self.assertEqual(original, data)


if __name__ == '__main__':
    unittest.main()
