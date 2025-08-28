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

# Phantom App imports
import tempfile
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
from phantom.vault import Vault
from phantom_common import paths

# Usage of the consts file is recommended
import umbrellav2_consts as consts
import requests
import json
import os
from bs4 import BeautifulSoup
from requests.auth import HTTPBasicAuth


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class UmbrellaV2Connector(BaseConnector):
    def __init__(self):
        # Call the BaseConnectors init first
        super(UmbrellaV2Connector, self).__init__()
        self._state = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url = None
        self._api_key = None
        self._key_secret = None
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
                if auth:
                    r = request_func(
                        endpoint,
                        auth=HTTPBasicAuth(self._api_key, self._key_secret),
                        json=json,
                        data=data,
                        headers=headers,
                        verify=verify,
                        params=params,
                    )
                else:
                    r = request_func(
                        endpoint,
                        json=json,
                        data=data,
                        headers=headers,
                        verify=verify,
                        params=params,
                    )
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

        self.debug_print(ret_val)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        self._state[consts.HTTP_JSON_ACCESS_TOKEN] = resp_json
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

    def _process_html_response(self, response, action_result):
        # An html response, treat it like an error
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

        if next_link:
            url = next_link
        else:
            url = "{0}{1}".format(self._base_url, endpoint)

        if headers is None:
            headers = {}

        if not self._access_token or is_force:
            self.save_progress("Generating a token")
            ret_val = self._get_token(action_result)

            if phantom.is_fail(ret_val):
                return action_result.get_status(), None

        headers.update(
            {
                "Authorization": "Bearer {0}".format(self._access_token),
                "Accept": "application/json",
                "Content-Type": "application/json",
            }
        )

        self.save_progress("Connecting to endpoint {}".format(endpoint))
        ret_val, resp_json = self._make_rest_call(
            url, action_result, verify, headers, params, data, json, method, download
        )

        # If token is expired, generate a new token
        message = action_result.get_message()
        self.debug_print(f"message: {message}")
        if message and ("Access" in message and "Forbidden" in message):
            self.save_progress("Bad token, generating a new one")
            ret_val = self._get_token(action_result)
            if phantom.is_fail(ret_val):
                return action_result.get_status(), None

            headers.update({"Authorization": "Bearer {0}".format(self._access_token)})

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
        action_result = ActionResult(dict(param))

        # NOTE: test connectivity does _NOT_ take any parameters
        # i.e. the param dictionary passed to this handler will be empty.
        # Also typically it does not add any data into an action_result either.
        # The status and progress messages are more important.

        self.save_progress("Connecting to endpoint")
        # make rest call
        ret_val, response = self._make_rest_call(
            consts.UMBRELLA_POLICIES_DESTINATION_LISTS,
            action_result,
            params=None,
            headers=None,
        )

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            # self.save_progress("Test Connectivity Failed.")
            return action_result.get_status()

        # Return success
        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

        # For now return Error with a message, in case of success we don't set the message, but use the summary
        # return action_result.set_status(phantom.APP_ERROR, "Action not yet implemented")

    def _handle_get_lists(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary

        # Required values can be accessed directly
        # required_parameter = param['required_parameter']

        # Optional values should use the .get() function
        # optional_parameter = param.get('optional_parameter', 'default_value')

        # make rest call
        ret_val, response = self._make_rest_call_helper(
            consts.UMBRELLA_POLICIES_DESTINATION_LISTS, action_result
        )

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()
            # pass

        # Add the response into the data section
        for data in response["data"]:
            action_result.add_data(data)

        # Add a dictionary that is made up of the most important values from data into the summary
        action_result.update_summary({})

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def __get_destinations(self, action_result, list_id):
        ret_val, response = self._make_rest_call_helper(
            consts.UMBRELLA_POLICIES_DESTINATION_LIST_DESTINATIONS.format(
                destinationListId=list_id
            ),
            action_result,
            params={"limit": 100},
            headers=None,
        )
        if response["status"]["code"] == 200:
            data = []
            # self.debug_print(response)
            for item in response["data"]:
                data.append(item)
            pages = int(int(response["meta"]["total"]) / 100) + 1
            self.debug_print("List contains {pages} pages".format(pages=pages))
            if response["meta"]["total"] > 100:
                for page in range(2, pages + 1):
                    ret_val, response = self._make_rest_call_helper(
                        consts.UMBRELLA_POLICIES_DESTINATION_LIST_DESTINATIONS.format(
                            destinationListId=list_id
                        ),
                        action_result,
                        params={"limit": 100, "page": page},
                        headers=None,
                    )
                    for item in response["data"]:
                        # self.debug_print(item)
                        data.append(item)
            return data
        else:
            return action_result.set_status(
                phantom.APP_ERROR, "Call to Get Destinations failed."
            )

    def _handle_get_destinations(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary

        # Required values can be accessed directly
        list_id = param["list_id"]

        # Optional values should use the .get() function
        search_value = param.get("search_value", "")

        data = self.__get_destinations(action_result, list_id)
        if data:
            if search_value:
                results = []
                found = False
                for row in data:
                    if search_value in row.values():
                        results.append(row)
                        action_result.add_data(row)
                        found = True
                if found:
                    action_result.update_summary(
                        {"output": "Search value found", "num_records": len(results)}
                    )
                else:
                    action_result.update_summary({"output": "Search value not found"})
            elif len(data) > 0:
                for row in data:
                    action_result.add_data(row)
                action_result.update_summary(
                    {"output": "All records returned", "num_records": len(data)}
                )
            else:
                action_result.update_summary({"output": "Something went wrong"})
            return action_result.set_status(phantom.APP_SUCCESS)
        else:
            return action_result.set_status(phantom.APP_FAILURE)

        # Add a dictionary that is made up of the most important values from data into the summary

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        # return action_result.set_status(phantom.APP_SUCCESS)

        # For now return Error with a message, in case of success we don't set the message, but use the summary
        # return action_result.set_status(phantom.APP_ERROR, "Action not yet implemented")

    def _handle_on_poll(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary

        # Required values can be accessed directly
        list_ids = self._list_ids
        self.debug_print(list_ids)
        umbrella_lists = list_ids.split(",")
        for umbrella_list in umbrella_lists:
            ret_val, response = self._make_rest_call_helper(
                consts.UMBRELLA_POLICIES_DESTINATION_LIST_ID.format(
                    destinationListId=umbrella_list.strip()
                ),
                action_result,
                params=None,
                headers=None,
            )
            self.debug_print(response["data"]["name"])
            list_name = response["data"]["name"]
            list_response = phantom.requests.get(
                self.get_phantom_base_url() + "rest/decided_list/{0}".format(list_name),
                verify=False,
            )
            list_data = self.__get_destinations(action_result, umbrella_list.strip())
            # self.debug_print(list_data)
            content_list = [["ID", "Destination", "Type", "Comment", "CreatedAt"]]
            for record in list_data:
                content_list.append(
                    [
                        record["id"],
                        record["destination"],
                        record["type"],
                        record["comment"],
                        record["createdAt"],
                    ]
                )
            # self.debug_print(content_list)
            create_dict = {"name": list_name, "content": content_list}
            if list_response.ok:
                self.debug_print("List Exists")
                phantom.requests.post(
                    self.get_phantom_base_url()
                    + "rest/decided_list/{0}".format(list_name),
                    data=json.dumps(create_dict),
                    verify=False,
                )
            else:
                self.debug_print("List Doesn't Exist")
                phantom.requests.post(
                    self.get_phantom_base_url() + "rest/decided_list",
                    data=json.dumps(create_dict),
                    verify=False,
                )

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            # return action_result.get_status()
            pass

        # Now post process the data,  uncomment code as you deem fit

        # Add the response into the data section
        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        # summary = action_result.update_summary({})
        # summary['num_data'] = len(action_result['data'])

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

        # For now return Error with a message, in case of success we don't set the message, but use the summary
        # return action_result.set_status(phantom.APP_ERROR, "Action not yet implemented")

    def handle_action(self, param):
        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == "get_lists":
            ret_val = self._handle_get_lists(param)

        if action_id == "get_destinations":
            ret_val = self._handle_get_destinations(param)

        if action_id == "on_poll":
            ret_val = self._handle_on_poll(param)

        if action_id == "test_connectivity":
            ret_val = self._handle_test_connectivity(param)

        return ret_val

    def initialize(self):
        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()
        """
        # Access values in asset config by the name

        # Required values can be accessed directly
        required_config_name = config['required_config_name']

        # Optional values should use the .get() function
        optional_config_name = config.get('optional_config_name')
        """

        self._base_url = consts.UMBRELLA_BASE_URL
        self._oauth_token_url = self._base_url + consts.OAUTH_TOKEN_URI
        self._timeout = consts.DEFAULT_REQUEST_TIMEOUT

        self._api_key = config.get("api_key")
        self._key_secret = config.get("key_secret")
        self._list_ids = config.get("list_ids_for_on_poll")

        self._access_token = self._state.get(consts.HTTP_JSON_ACCESS_TOKEN)

        return phantom.APP_SUCCESS

    def finalize(self):
        # Save the state, this data is saved across actions and app upgrades
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
