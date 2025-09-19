# Cisco Umbrella v2

Publisher: Splunk <br>
Connector Version: 1.0.0 <br>
Product Vendor: Cisco <br>
Product Name: Umbrella <br>
Minimum Product Version: 6.4.0

The Umbrella API was released in September 2022, providing a user-friendly and secure platform that enables users to build on, extend, and integrate with Umbrella. It facilitates the creation of multiple cross-platform workflows aggregating our market-leading threat intelligence with other security solutions to expand security enforcement, broaden visibility, and automate incident response

### Configuration variables

This table lists the configuration variables required to operate Cisco Umbrella v2. These variables are specified when configuring a Umbrella asset in Splunk SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**api_key** | required | password | Umbrella API Key |
**key_secret** | required | password | Umbrella Key Secret |

### Supported Actions

[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration <br>
[get lists](#action-get-lists) - Get all the destination lists in your organization <br>
[get destinations](#action-get-destinations) - Get destinations in a destination list

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

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**limit** | optional | Optional limit for number of results default all | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.limit | numeric | | |
action_result.data.\*.access | string | | |
action_result.data.\*.bundleTypeId | numeric | | |
action_result.data.\*.createdAt | numeric | | |
action_result.data.\*.id | numeric | `cisco umbrella destination list id` | |
action_result.data.\*.isGlobal | boolean | | |
action_result.data.\*.isMspDefault | boolean | | |
action_result.data.\*.markedForDeletion | boolean | | |
action_result.data.\*.meta.applicationCount | numeric | | |
action_result.data.\*.meta.destinationCount | numeric | | |
action_result.data.\*.meta.domainCount | numeric | | |
action_result.data.\*.meta.ipv4Count | numeric | | |
action_result.data.\*.meta.urlCount | numeric | | |
action_result.data.\*.modifiedAt | numeric | | |
action_result.data.\*.name | string | | |
action_result.data.\*.organizationId | numeric | | |
action_result.data.\*.thirdpartyCategoryId | string | | |
action_result.summary.total_lists | numeric | | |
action_result.message | string | | Total lists: 5 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get destinations'

Get destinations in a destination list

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**list_id** | required | The unique ID of the destination list | numeric | `cisco umbrella destination list id` |
**search_value** | optional | Optional value to search for in the list | string | |
**limit** | optional | Optional limit for number of results default all | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.limit | numeric | | |
action_result.parameter.list_id | numeric | `cisco umbrella destination list id` | 18474698 |
action_result.parameter.search_value | string | | test |
action_result.data | string | | |
action_result.data.\*.comment | string | | |
action_result.data.\*.createdAt | string | | 2025-09-12 12:31:30 |
action_result.data.\*.destination | string | | www.whatsapp.com |
action_result.data.\*.id | string | `cisco umbrella destination id` | 3534477 |
action_result.data.\*.type | string | | domain |
action_result.summary.matches_found | numeric | | |
action_result.summary.search_value | string | | |
action_result.summary.total_destinations | numeric | | |
action_result.message | string | | Search value: hotstar, Matches found: 1, Total destinations: 2 Total destinations: 2 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

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
