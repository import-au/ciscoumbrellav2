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


import json
import time

# Third-party imports
import requests
from bs4 import BeautifulSoup
from requests.auth import HTTPBasicAuth

# Phantom App imports
import phantom.app as phantom
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector

# Local imports
import umbrellav2_consts as consts
import encryption_helper


class RetVal(tuple):
    """Return value tuple for API responses.

    A custom tuple class to handle return values from API calls,
    typically containing status and response data.
    """

    def __new__(cls, val1, val2=None):
        """Create a new RetVal instance.

        Args:
            val1: First value (typically status)
            val2: Second value (typically response data)

        Returns:
            RetVal: New RetVal instance
        """
        return tuple.__new__(RetVal, (val1, val2))


class UmbrellaV2Connector(BaseConnector):
    """Cisco Umbrella V2 API Connector.

    This connector provides integration with Cisco Umbrella V2 API
    for managing destination lists and security policies.
    """

    def __init__(self) -> None:
        """Initialize the UmbrellaV2Connector."""
        super().__init__()
        self._state = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url = None
        self._api_key = None
        self._key_secret = None
        self._access_token = None
        self._oauth_token_url = None
        self._timeout = consts.DEFAULT_REQUEST_TIMEOUT
        self._token_expiry_time = None

    def _get_error_message_from_exception(self, e):
        """This method is used to get appropriate error message from the exception.
        :param e: Exception object
        :return: error message
        """

        error_code = None
        error_msg = consts.UMBRELLA_ERROR_MSG

        self.error_print("Error Occurred.", e)
        try:
            if hasattr(e, "args"):
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_msg = e.args[1]
                elif len(e.args) == 1:
                    error_msg = e.args[0]
        except Exception:
            self.debug_print("Error occurred while retrieving exception information")

        return "Error Code: {0}. Error Message: {1}".format(error_code, error_msg)

    def _make_rest_call(
        self,
        endpoint,
        action_result,
        headers=None,
        data=None,
        method="get",
        auth=False,
        **kwargs,
    ):
        """Function that makes the REST call to the app.

        Args:
            endpoint: REST endpoint URL
            action_result: ActionResult object for status tracking
            headers: Request headers (optional)
            data: Request body data (optional)
            method: HTTP method (default "get")
            auth: Use basic authentication (default False)
            **kwargs: Additional parameters (params, json, verify, etc.)

        Returns:
            RetVal: Tuple containing (status, response)
        """
        try:
            request_func = getattr(requests, method.lower())
        except AttributeError:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, f"Invalid HTTP method: {method}"
                ),
                None,
            )

        # Prepare request arguments
        request_kwargs = {
            "headers": headers,
            "data": data,
            "timeout": self._timeout,
            "verify": kwargs.get("verify", True),
        }

        # Add optional parameters from kwargs
        if "params" in kwargs:
            request_kwargs["params"] = kwargs["params"]
        if "json" in kwargs:
            request_kwargs["json"] = kwargs["json"]

        if auth:
            request_kwargs["auth"] = HTTPBasicAuth(self._api_key, self._key_secret)

        try:
            response = request_func(endpoint, **request_kwargs)

            return self._process_response(response, action_result)

        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR,
                    "Error Connecting to server. Details: {0}".format(error_message),
                ),
                None,
            )

    def _get_token(self, action_result):
        """This function is used to get a token via REST Call.
        :param action_result: Object of action result
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        data = {"grant_type": "client_credentials"}
        req_url = consts.UMBRELLA_BASE_URL + consts.OAUTH_TOKEN_URI
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        }

        ret_val, resp_json = self._make_rest_call(
            req_url, action_result, headers=headers, data=data, method="post", auth=True
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        self._access_token = resp_json[consts.HTTP_JSON_ACCESS_TOKEN]

        # Calculate token expiry time (current time + token lifetime)
        current_time = int(time.time())
        expires_in = resp_json.get("expires_in", consts.UMBRELLA_ACCESS_TOKEN_EXPIRY)
        self._token_expiry_time = current_time + expires_in

        # Store token and expiry time in state
        self._state["access_token"] = self._access_token
        self._state["token_expiry_time"] = self._token_expiry_time

        return action_result.set_status(
            phantom.APP_SUCCESS, "Successfully fetched access token"
        )

    def encrypt_state(self, encrypt_var, token_name):
        """Handle encryption of token.
        :param encrypt_var: Variable needs to be encrypted
        :return: encrypted variable
        """
        self.debug_print(consts.UMBRELLA_ENCRYPT_TOKEN.format(token_name))  # nosemgrep
        return encryption_helper.encrypt(encrypt_var, self.get_asset_id())

    def decrypt_state(self, decrypt_var, token_name):
        """Handle decryption of token.
        :param decrypt_var: Variable needs to be decrypted
        :return: decrypted variable
        """
        self.debug_print(consts.UMBRELLA_DECRYPT_TOKEN.format(token_name))  # nosemgrep
        return encryption_helper.decrypt(decrypt_var, self.get_asset_id())

    def _process_empty_response(self, response, action_result):
        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(
            action_result.set_status(
                phantom.APP_ERROR, "Empty response and no information in the header"
            ),
            None,
        )

    def _process_html_response(
        self, response: requests.Response, action_result: ActionResult
    ) -> RetVal:
        """Process HTML error response.

        Args:
            response: HTTP response object
            action_result: ActionResult object for status tracking

        Returns:
            RetVal: Tuple containing (status, None)
        """
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split("\n")
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = "\n".join(split_lines)
        except Exception:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(
            status_code, error_text
        )

        message = message.replace("{", "{{").replace("}", "}}")
        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):
        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR,
                    "Unable to parse JSON response. Error: {0}".format(str(e)),
                ),
                None,
            )

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
            r.status_code, r.text.replace("{", "{{").replace("}", "}}")
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):
        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, "add_debug_data"):
            action_result.add_debug_data({"r_status_code": r.status_code})
            action_result.add_debug_data({"r_text": r.text})
            action_result.add_debug_data({"r_headers": r.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        if "json" in r.headers.get("Content-Type", ""):
            return self._process_json_response(r, action_result)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if "html" in r.headers.get("Content-Type", ""):
            return self._process_html_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_response(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
            r.status_code, r.text.replace("{", "{{").replace("}", "}}")
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call_helper(self, endpoint, action_result, params=None, **kwargs):
        """Helper function for making authenticated REST calls to the Umbrella API.

        Args:
            endpoint: API endpoint (will be appended to base URL)
            action_result: ActionResult object for status tracking
            params: Request parameters (optional)
            **kwargs: Additional parameters for rare cases

        Returns:
            Tuple: (status, response_data)
        """
        # Ensure we have a valid token
        if not self._access_token or self._is_token_expired():
            self.save_progress("Generating access token")
            ret_val = self._get_token(action_result)
            if phantom.is_fail(ret_val):
                return action_result.get_status(), None

        # Prepare headers with authentication
        request_headers = {
            "Authorization": f"Bearer {self._access_token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

        # Construct full URL
        url = f"{self._base_url}{endpoint}"

        # Prepare call arguments
        call_kwargs = {"headers": request_headers}
        if params:
            call_kwargs["params"] = params

        # Add any additional kwargs (for rare cases)
        call_kwargs.update(kwargs)

        self.save_progress(f"Connecting to endpoint {endpoint}")
        ret_val, resp_json = self._make_rest_call(url, action_result, **call_kwargs)

        # Handle token expiration with retry
        if phantom.is_fail(ret_val) and self._is_token_error(
            action_result.get_message()
        ):
            self.save_progress("Token expired, generating new token")
            ret_val = self._get_token(action_result)
            if phantom.is_fail(ret_val):
                return action_result.get_status(), None

            # Update authorization header and retry
            request_headers["Authorization"] = f"Bearer {self._access_token}"
            call_kwargs["headers"] = request_headers
            self.save_progress(f"Retrying connection to endpoint {endpoint}")
            ret_val, resp_json = self._make_rest_call(url, action_result, **call_kwargs)

        if phantom.is_fail(ret_val):
            return action_result.get_status(), None

        return phantom.APP_SUCCESS, resp_json

    def _is_token_error(self, error_message):
        """Check if the error message indicates a token-related issue.

        Args:
            error_message: Error message from API response

        Returns:
            bool: True if error is token-related
        """
        if not error_message:
            return False

        token_error_indicators = [
            "Access",
            "Forbidden",
            "Unauthorized",
            "401",
            "403",
            "token",
            "authentication",
            "expired",
        ]

        error_lower = error_message.lower()
        return any(
            indicator.lower() in error_lower for indicator in token_error_indicators
        )

    def _handle_test_connectivity(self, param):
        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress("Testing connectivity to Cisco Umbrella API")

        # Test API connectivity by fetching destination lists
        ret_val, response = self.__get_paginated_data(
            action_result,
            consts.UMBRELLA_POLICIES_DESTINATION_LISTS,
            limit=1,
            error_msg="Failed to get lists",
        )

        if phantom.is_fail(ret_val):
            self.save_progress("Test Connectivity Failed")
            return action_result.get_status()

        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS, "Test Connectivity Passed")

    def _handle_get_lists(self, param):
        """Get destination lists from Cisco Umbrella.

        Args:
            param: Action parameters

        Returns:
            int: phantom.APP_SUCCESS or phantom.APP_ERROR
        """
        self.save_progress(f"Executing action: {self.get_action_identifier()}")

        action_result = self.add_action_result(ActionResult(dict(param)))

        limit = param.get("limit")

        ret_val, data = self.__get_paginated_data(
            action_result,
            consts.UMBRELLA_POLICIES_DESTINATION_LISTS,
            limit=limit,
            error_msg="Failed to get lists",
        )
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Add response data to action result
        for val in data:
            action_result.add_data(val)
        action_result.update_summary({"total_lists": len(data)})

        return action_result.set_status(phantom.APP_SUCCESS)

    def __get_paginated_data(
        self, action_result, endpoint, limit=None, error_msg="Failed to fetch data"
    ):
        """Get paginated data from API with optional user-specified limit.

        Args:
            action_result: ActionResult object for status tracking
            endpoint: API endpoint to call
            limit: Optional user-specified limit for results
            error_msg: Custom error message for failures

        Returns:
            Tuple[int, List[Dict]]: Status and list of data items
        """
        page_size = min(limit, 100) if limit else 100  # API max is 100
        ret_val, response = self._make_rest_call_helper(
            endpoint,
            action_result,
            params={"limit": page_size},
        )

        if phantom.is_fail(ret_val) or not response:
            return action_result.set_status(phantom.APP_ERROR, error_msg), []

        if response.get("status", {}).get("code") != 200:
            return action_result.set_status(
                phantom.APP_ERROR, response.get("error", error_msg)
            ), []

        data = list(response.get("data", []))
        total_items = response.get("meta", {}).get("total", 0)

        # If user specified a limit and we have enough data, return early
        if limit and len(data) >= limit:
            return phantom.APP_SUCCESS, data[:limit]

        # Calculate how many more items we need
        items_needed = limit - len(data) if limit else total_items - len(data)

        # Continue pagination if we need more data
        if items_needed > 0 and total_items > page_size:
            remaining_pages = min(
                (total_items - 1) // page_size,
                (items_needed + page_size - 1) // page_size,  # Round up division
            )
            self.debug_print(f"Fetching {remaining_pages} additional pages")

            for page in range(2, remaining_pages + 2):
                ret_val, page_response = self._make_rest_call_helper(
                    endpoint,
                    action_result,
                    params={"limit": page_size, "page": page},
                )

                if phantom.is_success(ret_val) and page_response:
                    page_data = page_response.get("data", [])
                    data.extend(page_data)
                    items_needed -= len(page_data)

                    # Early termination if we have enough items
                    if items_needed <= 0:
                        break

        # Apply final limit if specified
        if limit:
            data = data[:limit]

        return phantom.APP_SUCCESS, data

    def _handle_get_destinations(self, param):
        """Get destinations from a specific destination list.

        Args:
            param: Action parameters containing list_id and optional search_value

        Returns:
            int: phantom.APP_SUCCESS or phantom.APP_ERROR
        """
        self.save_progress(f"Executing action: {self.get_action_identifier()}")

        action_result = self.add_action_result(ActionResult(dict(param)))

        list_id = param["list_id"]
        search_value = param.get("search_value", "")
        limit = param.get("limit")

        # Get destinations from the list
        ret_val, data = self.__get_paginated_data(
            action_result,
            consts.UMBRELLA_POLICIES_DESTINATION_LIST_DESTINATIONS.format(
                destinationListId=list_id
            ),
            limit=limit,
            error_msg="Failed to get destinations",
        )
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Optimized filtering with early termination and better search
        if search_value:
            search_lower = search_value.lower()
            matches_found = 0

            # Optimized search with generator expression
            for row in data:
                if any(search_lower in str(value).lower() for value in row.values()):
                    action_result.add_data(row)
                    matches_found += 1

            action_result.update_summary(
                {
                    "search_value": search_value,
                    "matches_found": matches_found,
                    "total_destinations": len(data),
                }
            )
        else:
            for val in data:
                action_result.add_data(val)
            action_result.update_summary({"total_destinations": len(data)})

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):
        """Route actions to appropriate handlers.

        Args:
            param: Action parameters

        Returns:
            int: phantom.APP_SUCCESS or phantom.APP_ERROR
        """
        action_id = self.get_action_identifier()
        self.debug_print(f"Executing action: {action_id}")

        # Action routing with improved error handling
        action_mapping = {
            "test_connectivity": self._handle_test_connectivity,
            "get_lists": self._handle_get_lists,
            "get_destinations": self._handle_get_destinations,
        }

        if action_id in action_mapping:
            action_function = action_mapping[action_id]
            return action_function(param)
        else:
            return self.set_status(
                phantom.APP_ERROR, f"Unsupported action: {action_id}"
            )

    def _reset_state(self):
        self._state = {"app_version": self.get_app_json().get("app_version")}

    def initialize(self) -> int:
        """Initialize the connector with configuration and state.

        Returns:
            int: phantom.APP_SUCCESS or phantom.APP_ERROR
        """

        # Get asset configuration
        config = self.get_config()

        self._state = self.load_state()
        if not isinstance(self._state, dict):
            self.debug_print("Resetting the state file with the default format")
            self._reset_state()
            return self.set_status(
                phantom.APP_ERROR, consts.UMBRELLA_STATE_FILE_CORRUPT_ERROR
            )

        # Validate required configuration
        self._api_key = config.get("api_key")
        self._key_secret = config.get("key_secret")

        if not (self._api_key and self._key_secret):
            self.debug_print("Missing required API credentials")
            return phantom.APP_ERROR

        # Set up API configuration
        self._base_url = consts.UMBRELLA_BASE_URL
        self._oauth_token_url = self._base_url + consts.OAUTH_TOKEN_URI
        self._timeout = consts.DEFAULT_REQUEST_TIMEOUT

        if self.get_action_identifier() == "test_connectivity":
            return phantom.APP_SUCCESS

        # Load existing token from state if available
        self._load_token_from_state()

        return phantom.APP_SUCCESS

    def _is_token_expired(self):
        """Check if the current access token is expired or about to expire.

        Returns:
            bool: True if token is expired or about to expire, False otherwise
        """
        if not self._token_expiry_time:
            return True

        current_time = int(time.time())
        # Add buffer time to refresh token before it actually expires
        return current_time >= (
            self._token_expiry_time - consts.UMBRELLA_TOKEN_EXPIRY_BUFFER
        )

    def _load_token_from_state(self):
        try:
            if self._state.get(consts.UMBRELLA_STATE_IS_ENCRYPTED):
                encrypted_token = self._state.get("access_token")
                if encrypted_token:
                    self._access_token = self.decrypt_state(encrypted_token, "access")
                    self._token_expiry_time = self._state.get("token_expiry_time")
        except Exception as e:
            self.debug_print(
                f"{consts.UMBRELLA_DECRYPTION_ERROR}: {self._get_error_message_from_exception(e)}"
            )
            # Clear corrupted token data
            self._reset_state()

    def finalize(self):
        try:
            if self._access_token:
                self._state["access_token"] = self.encrypt_state(
                    self._access_token, "access"
                )
                self._state["token_expiry_time"] = self._token_expiry_time

            self._state[consts.UMBRELLA_STATE_IS_ENCRYPTED] = True
        except Exception as e:
            self.error_print(
                f"{consts.UMBRELLA_ENCRYPTION_ERROR}: {self._get_error_message_from_exception(e)}"
            )
            return self.set_status(phantom.APP_ERROR, consts.UMBRELLA_ENCRYPTION_ERROR)

        self.save_state(self._state)
        return phantom.APP_SUCCESS


def main():
    import argparse

    argparser = argparse.ArgumentParser()

    argparser.add_argument("input_test_json", help="Input Test JSON file")
    argparser.add_argument("-u", "--username", help="username", required=False)
    argparser.add_argument("-p", "--password", help="password", required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if username is not None and password is None:
        # User specified a username but not a password, so ask
        import getpass

        password = getpass.getpass("Password: ")

    if username and password:
        try:
            login_url = UmbrellaV2Connector._get_phantom_base_url() + "/login"

            print("Accessing the Login page")
            r = requests.get(login_url, verify=False)
            csrftoken = r.cookies["csrftoken"]

            data = dict()
            data["username"] = username
            data["password"] = password
            data["csrfmiddlewaretoken"] = csrftoken

            headers = dict()
            headers["Cookie"] = "csrftoken=" + csrftoken
            headers["Referer"] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=False, data=data, headers=headers)
            session_id = r2.cookies["sessionid"]
        except Exception as e:
            print("Unable to get session id from the platform. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = UmbrellaV2Connector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json["user_session_token"] = session_id
            connector._set_csrf_info(csrftoken, headers["Referer"])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)


if __name__ == "__main__":
    main()
