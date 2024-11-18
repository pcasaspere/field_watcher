import requests
import json

from .Config import ConfigManager


class ApiResponse:
    def __init__(self):
        self.status_code = 0
        self.success = False
        self.detail = ""
        self.data = None
        self.errors = []

    def __str__(self) -> str:
        return f"Status Code: {self.status_code}\nSuccess: {self.success}\nDetail: {self.detail}\nData: {self.data}\nErrors: {self.errors}"


class ApiManager:
    config: ConfigManager

    def __init__(self, config: ConfigManager):
        self.config = config

        self.headers = {
            'Accept': 'application/json',
            'Accept-Media-Type': 'application/json',
            'Content-Type': 'application/json'
        }

        if self.config.token:
            self.headers['Authorization'] = f'Bearer {self.config.token}'

    def sync(self, data: list[dict]) -> ApiResponse:

        apiResponse = ApiResponse()

        try:

            response = requests.post(
                self.config.endpoint, data=json.dumps(data), headers=self.headers)

            try:
                apiResponse.data = response.json()
                apiResponse.detail = apiResponse.data.get('detail', '')
            except requests.exceptions.JSONDecodeError:
                apiResponse.data = response.content

            success = response.status_code >= 200 and response.status_code < 300

            if not success:
                apiResponse.success = False
                apiResponse.status_code = response.status_code
                apiResponse.detail = f"API returned status code {response.status_code}"
                apiResponse.errors = apiResponse.data or []
                return apiResponse

            apiResponse.success = True
            apiResponse.status_code = response.status_code

            return apiResponse

        except Exception as e:
            apiResponse.success = False
            apiResponse.detail = str(e)
            return apiResponse
