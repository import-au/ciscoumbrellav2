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
import os
import tempfile

# Third-party imports
import requests
from bs4 import BeautifulSoup
from requests.auth import HTTPBasicAuth

# Phantom App imports
import phantom.app as phantom
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector
from phantom.vault import Vault
from phantom_common import paths

# Local imports
import umbrellav2_consts as consts


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
        super(UmbrellaV2Connector, self).__init__()
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
        self._list_ids = None
        self.access_token_retry = True

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
        verify=True,
        headers=None,
        params=None,
        data=None,
        json=None,
        method="get",
        download=False,
        auth=False,
    ):
        """Function that makes the REST call to the app.
        :param endpoint: REST endpoint that needs to appended to the service address
        :param action_result: object of ActionResult class
        :param verify: verify server certificate (Default True)
        :param headers: request headers
        :param params: request parameters
        :param data: request body
        :param json: JSON object
        :param method: GET/POST/PUT/DELETE/PATCH (Default will be GET)
        :param download: use streaming for the file download to handle large files
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message),
        response obtained by making an API call
        """

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Invalid method: {0}".format(method)
                ),
                resp_json,
            )

        try:
            if download:
                if hasattr(Vault, "get_vault_tmp_dir"):
                    fd, tmp_file_path = tempfile.mkstemp(dir=Vault.get_vault_tmp_dir())
                else:
                    vault_tmp = os.path.join(paths.PHANTOM_VAULT, "tmp")
                    fd, tmp_file_path = tempfile.mkstemp(dir=vault_tmp)
                os.close(fd)
                if auth:
                    r = request_func(
                        endpoint,
                        auth=HTTPBasicAuth(self._api_key, self._key_secret),
                        json=json,
                        data=data,
                        headers=headers,
                        params=params,
                        stream=True,
                    )
                else:
                    r = request_func(
                        endpoint,
                        json=json,
                        data=data,
                        headers=headers,
                        params=params,
                        stream=True,
                    )
                if 200 <= r.status_code < 399:
                    with open(tmp_file_path, "wb") as fp:
                        for chunk in r.iter_content(chunk_size=10 * 1024 * 1024):
                            fp.write(chunk)
                    return RetVal(phantom.APP_SUCCESS, tmp_file_path)
                self.debug_print(
                    "Error while downloading file. StatusCode: {}, text: {}".format(
                        r.status_code, r.text
                    )
                )
            else:
                # Prepare common request kwargs
                request_kwargs = {
                    "json": json,
                    "data": data,
                    "headers": headers,
                    "verify": verify,
                    "params": params,
                    "timeout": self._timeout,
                }

                if auth:
                    request_kwargs["auth"] = HTTPBasicAuth(
                        self._api_key, self._key_secret
                    )

                r = request_func(endpoint, **request_kwargs)
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR,
                    "Error Connecting to server. Details: {0}".format(error_message),
                ),
                resp_json,
            )

        return self._process_response(r, action_result)

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

        return action_result.set_status(
            phantom.APP_SUCCESS, "Successfully fetched access token"
        )

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

    def _make_rest_call_helper(
        self,
        endpoint,
        action_result,
        verify=True,
        headers=None,
        params=None,
        data=None,
        json=None,
        method="get",
        download=False,
        next_link=None,
        is_force=False,
    ):
        """Function that helps to set a REST call to the app.
        :param endpoint: REST endpoint that needs to appended to the service address
        :param action_result: object of ActionResult class
        :param verify: verify server certificate (Default True)
        :param headers: request headers
        :param params: request parameters
        :param data: request body
        :param json: JSON object
        :param method: GET/POST/PUT/DELETE/PATCH (Default will be GET)
        :param download: use streaming for the file download to handle large files
        :param next_link: used for pagination, next_link is returned in the API response
        :param is_force: ignore the token available in the state file
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message),
        response obtained by making an API call
        """

        url = f"{self._base_url}{endpoint}"

        if headers is None:
            headers = {}

        if not self._access_token or is_force:
            self.save_progress("Generating a token")
            ret_val = self._get_token(action_result)

            if phantom.is_fail(ret_val):
                return action_result.get_status(), None

        # Add authentication and content headers
        headers.update(
            {
                "Authorization": f"Bearer {self._access_token}",
                "Accept": "application/json",
                "Content-Type": "application/json",
            }
        )

        self.save_progress(f"Connecting to endpoint {endpoint}")
        ret_val, resp_json = self._make_rest_call(
            url, action_result, verify, headers, params, data, json, method, download
        )

        # Handle token expiration by retrying with new token
        message = action_result.get_message()
        self.debug_print(f"API response message: {message}")

        if message and ("Access" in message and "Forbidden" in message):
            self.save_progress("Token expired, generating new token")
            ret_val = self._get_token(action_result)

            if phantom.is_fail(ret_val):
                return action_result.get_status(), None

            headers.update({"Authorization": f"Bearer {self._access_token}"})

            self.save_progress("Connecting to endpoint {}".format(endpoint))
            ret_val, resp_json = self._make_rest_call(
                url,
                action_result,
                verify,
                headers,
                params,
                data,
                json,
                method,
                download,
            )

        if phantom.is_fail(ret_val):
            return action_result.get_status(), None

        return phantom.APP_SUCCESS, resp_json

    def _handle_test_connectivity(self, param):
        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress("Testing connectivity to Cisco Umbrella API")

        # Test API connectivity by fetching destination lists
        ret_val, response = self._make_rest_call_helper(
            consts.UMBRELLA_POLICIES_DESTINATION_LISTS,
            action_result,
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

        # Fetch destination lists from API
        ret_val, response = self._make_rest_call_helper(
            consts.UMBRELLA_POLICIES_DESTINATION_LISTS, action_result
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Add response data to action result
        action_result.add_data(response.get("data", []))
        action_result.update_summary({"total_lists": len(response.get("data", []))})

        return action_result.set_status(phantom.APP_SUCCESS)

    def __get_destinations(self, action_result, list_id):
        """Get all destinations from a specific destination list with caching.

        Args:
            action_result: ActionResult object for status tracking
            list_id: ID of the destination list

        Returns:
            Union[List[Dict], int]: List of destinations or error status
        """

        endpoint = consts.UMBRELLA_POLICIES_DESTINATION_LIST_DESTINATIONS.format(
            destinationListId=list_id
        )

        page_size = 100  # max supported
        ret_val, response = self._make_rest_call_helper(
            endpoint,
            action_result,
            params={"limit": page_size},
        )

        if phantom.is_fail(ret_val) or not response:
            return action_result.set_status(
                phantom.APP_ERROR, "Failed to get destinations"
            )

        if response.get("status", {}).get("code") != 200:
            return action_result.set_status(
                phantom.APP_ERROR, "API returned non-200 status"
            )

        data = list(response.get("data", []))
        total_items = response.get("meta", {}).get("total", 0)

        # Optimized pagination with concurrent requests if needed
        if total_items > page_size:
            remaining_pages = [(total_items - 1) // page_size]
            self.debug_print(f"Fetching {remaining_pages[0]} additional pages")

            # Sequential pagination (can be made concurrent if needed)
            for page in range(2, remaining_pages[0] + 2):
                ret_val, page_response = self._make_rest_call_helper(
                    endpoint,
                    action_result,
                    params={"limit": page_size, "page": page},
                )

                if phantom.is_success(ret_val) and page_response:
                    page_data = page_response.get("data", [])
                    data.extend(page_data)

                    # Early termination if we got all items
                    if len(data) >= total_items:
                        break
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

        # Get destinations from the list
        ret_val, data = self.__get_destinations(action_result, list_id)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Optimized filtering with early termination and better search
        if search_value:
            search_lower = search_value.lower()
            filtered_results = []

            # Optimized search with generator expression
            for row in data:
                if any(search_lower in str(value).lower() for value in row.values()):
                    filtered_results.append(row)

            action_result.add_data(filtered_results)
            action_result.update_summary(
                {
                    "search_value": search_value,
                    "matches_found": len(filtered_results),
                    "total_destinations": len(data),
                }
            )
        else:
            action_result.add_data(data)
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

        if action_id in list(action_mapping.keys()):
            action_function = action_mapping[action_id]
            action_execution_status = action_function(param)

        return action_execution_status

    def initialize(self) -> int:
        """Initialize the connector with configuration and state.

        Returns:
            int: phantom.APP_SUCCESS or phantom.APP_ERROR
        """

        # Get asset configuration
        config = self.get_config()

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
