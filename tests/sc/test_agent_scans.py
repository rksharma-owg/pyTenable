import pytest
import responses
from responses.matchers import json_params_matcher, query_param_matcher

from tenable.errors import UnexpectedValueError


def _response(value):
    return {
        'type': 'regular',
        'response': value,
        'error_code': 0,
        'error_msg': '',
        'warnings': [],
        'timestamp': 1,
    }


@responses.activate
def test_agent_scans_list_requests_selected_fields(tsc):
    scans = {'usable': [{'id': '1'}], 'manageable': [{'id': '1'}]}
    responses.get(
        'https://nourl/rest/agentScan',
        match=[query_param_matcher({'fields': 'id,name,status'})],
        json=_response(scans),
    )

    assert tsc.agent_scans.list(fields=['id', 'name', 'status']) == scans


@responses.activate
def test_agent_scans_create_builds_documented_payload(tsc):
    created = {'id': '8', 'name': 'Weekly agents'}
    responses.post(
        'https://nourl/rest/agentScan',
        match=[
            json_params_matcher(
                {
                    'name': 'Weekly agents',
                    'type': 'policy',
                    'description': 'Production agents',
                    'nessusManager': {'id': 7},
                    'repository': {'id': 12},
                    'agentGroups': [{'id': 3}, {'id': 4}],
                    'policy': {'id': 42},
                    'scanWindow': '90',
                    'triggeredScanInterval': -1,
                    'triggeredScanFilename': '',
                    'schedule': {'type': 'never'},
                    'reports': [{'id': 6, 'reportSource': 'individual'}],
                }
            )
        ],
        json=_response(created),
    )

    assert (
        tsc.agent_scans.create(
            'Weekly agents',
            manager_id=7,
            repo=12,
            description='Production agents',
            agent_group_ids=[3, 4],
            policy_id=42,
            scan_window=90,
            triggered_scan_interval=-1,
            triggered_scan_filename='',
            schedule={'type': 'never'},
            reports=[{'id': 6, 'reportSource': 'individual'}],
        )
        == created
    )


@responses.activate
def test_agent_scans_create_requires_scan_type(tsc):
    with pytest.raises(UnexpectedValueError):
        tsc.agent_scans.create('Weekly agents', manager_id=7, repo=12)


@responses.activate
def test_agent_scans_policy_id_overrides_conflicting_type(tsc):
    created = {'id': '8', 'name': 'Weekly agents'}
    responses.post(
        'https://nourl/rest/agentScan',
        match=[
            json_params_matcher(
                {
                    'name': 'Weekly agents',
                    'type': 'policy',
                    'nessusManager': {'id': 7},
                    'repository': {'id': 12},
                    'policy': {'id': 42},
                }
            )
        ],
        json=_response(created),
    )

    assert (
        tsc.agent_scans.create(
            'Weekly agents',
            manager_id=7,
            repo=12,
            type='plugin',
            policy_id=42,
        )
        == created
    )


@pytest.mark.parametrize('interval', [0, 11, 1001])
@responses.activate
def test_agent_scans_create_rejects_invalid_triggered_interval(tsc, interval):
    with pytest.raises(UnexpectedValueError):
        tsc.agent_scans.create(
            'Triggered agents',
            manager_id=7,
            repo=12,
            type='plugin',
            triggered_scan_interval=interval,
        )


@responses.activate
def test_agent_scans_empty_schedule_uses_api_default(tsc):
    created = {'id': '8', 'name': 'Weekly agents'}
    responses.post(
        'https://nourl/rest/agentScan',
        match=[
            json_params_matcher(
                {
                    'name': 'Weekly agents',
                    'type': 'plugin',
                    'nessusManager': {'id': 7},
                    'repository': {'id': 12},
                    'schedule': {'type': 'template'},
                }
            )
        ],
        json=_response(created),
    )

    assert (
        tsc.agent_scans.create(
            'Weekly agents',
            manager_id=7,
            repo=12,
            type='plugin',
            schedule={},
        )
        == created
    )


@responses.activate
def test_agent_scans_details_requests_selected_fields(tsc):
    scan = {'id': '8', 'name': 'Weekly agents'}
    responses.get(
        'https://nourl/rest/agentScan/8',
        match=[query_param_matcher({'fields': 'id,name'})],
        json=_response(scan),
    )

    assert tsc.agent_scans.details(8, fields=['id', 'name']) == scan


@responses.activate
def test_agent_scans_edit_sends_only_changed_fields(tsc):
    updated = {'id': '8', 'name': 'Daily agents'}
    responses.patch(
        'https://nourl/rest/agentScan/8',
        match=[
            json_params_matcher(
                {
                    'name': 'Daily agents',
                    'agentGroups': [{'id': 5}],
                    'schedule': {
                        'type': 'ical',
                        'start': 'TZID=UTC:20260101T010000',
                        'repeatRule': 'FREQ=DAILY;INTERVAL=1',
                    },
                }
            )
        ],
        json=_response(updated),
    )

    assert (
        tsc.agent_scans.edit(
            8,
            name='Daily agents',
            agent_group_ids=[5],
            schedule={
                'type': 'ical',
                'start': 'TZID=UTC:20260101T010000',
                'repeatRule': 'FREQ=DAILY;INTERVAL=1',
            },
        )
        == updated
    )


@responses.activate
def test_agent_scans_delete_returns_api_response(tsc):
    responses.delete(
        'https://nourl/rest/agentScan/8',
        json=_response(''),
    )

    assert tsc.agent_scans.delete(8) == ''


@responses.activate
def test_agent_scans_launch_returns_scan_result(tsc):
    launched = {'agentScanID': '8', 'jobID': '93484', 'status': 'Queued'}
    responses.post(
        'https://nourl/rest/agentScan/8/launch',
        match=[json_params_matcher({})],
        json=_response(launched),
    )

    assert tsc.agent_scans.launch(8) == launched
