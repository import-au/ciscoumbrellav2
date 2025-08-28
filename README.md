# Umbrella v2

Publisher: Splunk Community <br>
Connector Version: 3.4.0 <br>
Product Vendor: Cisco <br>
Product Name: Umbrella <br>
Minimum Product Version: 6.4.0

The Umbrella API was released in September 2022, providing a user-friendly and secure platform that enables users to build on, extend, and integrate with Umbrella. It facilitates the creation of multiple cross-platform workflows aggregating our market-leading threat intelligence with other security solutions to expand security enforcement, broaden visibility, and automate incident response

### Configuration variables

This table lists the configuration variables required to operate Umbrella v2. These variables are specified when configuring a Umbrella asset in Splunk SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**api_key** | required | password | Umbrella API Key |
**key_secret** | required | password | Umbrella Key Secret |
**list_ids_for_on_poll** | optional | string | Comma-separated list of Umbrella List IDs to ingest when 'on poll' is executed |

### Supported Actions

[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration <br>
[get lists](#action-get-lists) - Get all the destination lists in your organization <br>
[get destinations](#action-get-destinations) - Get destinations in a destination list <br>
[on poll](#action-on-poll) - List Ingestion

## action: 'test connectivity'

Validate the asset configuration for connectivity using supplied configuration

Type: **test** <br>
Read only: **True**

#### Action Parameters

No parameters are required for this action

#### Action Output

No Output

## action: 'get lists'

Get all the destination lists in your organization

Type: **generic** <br>
Read only: **True**

#### Action Parameters

No parameters are required for this action

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.data.\*.id | numeric | | |
action_result.data.\*.name | string | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'get destinations'

Get destinations in a destination list

Type: **generic** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**list_id** | required | The unique ID of the destination list | numeric | |
**search_value** | optional | Optional value to search for in the list | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.data.\*.id | numeric | | |
action_result.data.\*.type | string | | |
action_result.data.\*.comment | string | | |
action_result.data.\*.destination | string | | |
action_result.data.\*.createdAt | string | | |
action_result.parameter.list_id | numeric | | |
action_result.parameter.search_value | string | | |
action_result.status | string | | success failed |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'on poll'

List Ingestion

Type: **ingest** <br>
Read only: **False**

#### Action Parameters

No parameters are required for this action

#### Action Output

No Output

______________________________________________________________________

Auto-generated Splunk SOAR Connector documentation.

Copyright 2025 Splunk Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
