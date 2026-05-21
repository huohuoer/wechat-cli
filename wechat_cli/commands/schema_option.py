"""Shared --schema option decorator for all commands."""

import functools

import click

from ..output.schemas import output_schema


def schema_option(command_name):
    """Decorator that adds an eager --schema flag to a Click command.

    When --schema is passed, the command outputs its JSON schema and exits
    immediately, before Click validates required arguments.
    """
    def decorator(func):
        @click.option("--schema", "show_schema", is_flag=True, is_eager=True,
                      expose_value=False, callback=lambda ctx, param, value: _handle_schema(ctx, command_name, value),
                      help="Output JSON schema for this command and exit")
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            return func(*args, **kwargs)
        return wrapper
    return decorator


def _handle_schema(ctx, command_name, value):
    if value:
        output_schema(command_name)
        ctx.exit(0)
