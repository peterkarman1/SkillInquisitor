from urllib.request import urlopen


def check(url: str) -> int:
    with urlopen(url) as response:  # noqa: S310
        return response.status
