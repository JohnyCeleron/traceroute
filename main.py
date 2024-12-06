from src.request_builder import TracerouteRequest
from src.response_builder import TracerouteResponse
from console_parser import get_arguments


def main():
    arguments = get_arguments()
    request = TracerouteRequest.from_argument_parser(arguments)
    response = TracerouteResponse.from_request(request)
    print(response)


if __name__ == '__main__':
    main()