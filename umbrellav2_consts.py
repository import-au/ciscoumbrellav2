# Copyright (c) 2025 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# API Configuration
DEFAULT_REQUEST_TIMEOUT = 30  # in seconds
HTTP_JSON_ACCESS_TOKEN = "access_token"
OAUTH_TOKEN_URI = "/auth/v2/token"

# Error Messages
UMBRELLA_ERROR_MSG = (
    "Unknown error occurred. Please check the asset configuration "
    "and/or action parameters"
)
UMBRELLA_STATE_FILE_CORRUPT_ERROR = (
    "Error occurred while loading the state file due to its unexpected format. "
    "Resetting the state file with the default format. Please try again."
)

UMBRELLA_STATE_IS_ENCRYPTED = "is_encrypted"

# Token management constants
UMBRELLA_TOKEN_EXPIRY_BUFFER = 300  # 5 minutes buffer before actual expiry
UMBRELLA_ACCESS_TOKEN_EXPIRY = 3600  # 1 hour in seconds

# Encryption and decryption messages
UMBRELLA_ENCRYPT_TOKEN = "Encrypting the {} token"
UMBRELLA_DECRYPT_TOKEN = "Decrypting the {} token"
UMBRELLA_ENCRYPTION_ERROR = "Error occurred while encrypting the state file"
UMBRELLA_DECRYPTION_ERROR = "Error occurred while decrypting the state file"

# API Base URL and Endpoints
UMBRELLA_BASE_URL = "https://api.umbrella.com"
UMBRELLA_POLICIES_DESTINATION_LISTS = "/policies/v2/destinationlists"
UMBRELLA_POLICIES_DESTINATION_LIST_ID = (
    "/policies/v2/destinationlists/{destinationListId}"
)
UMBRELLA_POLICIES_DESTINATION_LIST_DESTINATIONS = (
    "/policies/v2/destinationlists/{destinationListId}/destinations"
)
