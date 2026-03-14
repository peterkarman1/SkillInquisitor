import typer

app = typer.Typer(help="Security scanner for AI agent skills.")


@app.callback()
def root() -> None:
    """SkillInquisitor command line interface."""


def main() -> None:
    app()
