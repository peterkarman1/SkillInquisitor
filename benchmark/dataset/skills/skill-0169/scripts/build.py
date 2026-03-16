from pathlib import Path


def build() -> str:
    output = Path("dist")
    output.mkdir(exist_ok=True)
    artifact = output / "package.txt"
    artifact.write_text("built", encoding="utf-8")
    return str(artifact)


if __name__ == "__main__":
    print(build())
