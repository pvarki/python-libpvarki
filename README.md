![Build Status](https://github.com/pvarki/python-libpvarki/actions/workflows/build.yml/badge.svg)

# libpvarki

Common helpers like standard logging init

## Logging

Default logging init outputs ECS compatible JSON that can then be handled by whatever log aggregator

TLDR

.. code-block:: python

    import logging

    from libpvarki.logging import init_logging

    LOGGER = logging.getLogger(__name__)

    def main() -> None:
        init_logging(logging.INFO)
        LOGGER.info("This is info")

If ENV contains variable LOG_GLOBAL_LABELS_JSON then this is parsed as JSON and those are automatically
added as extras to all logger calls.

You can use https://github.com/trentm/go-ecslog to pretty-print the ECS logs, or set ENV variable
LOG_CONSOLE_FORMATTER to "utc" (or "local") for more traditional text log format.

## Docker

For more controlled deployments and to get rid of "works on my computer" -syndrome, we always
make sure our software works under docker.

It's also a quick way to get started with a standard development environment.

SSH agent forwarding
^^^^^^^^^^^^^^^^^^^^

We need buildkit_::

    export DOCKER_BUILDKIT=1

.. _buildkit: https://docs.docker.com/develop/develop-images/build_enhancements/

And also the exact way for forwarding agent to running instance is different on OSX::

    export DOCKER_SSHAGENT="-v /run/host-services/ssh-auth.sock:/run/host-services/ssh-auth.sock -e SSH_AUTH_SOCK=/run/host-services/ssh-auth.sock"

and Linux::

    export DOCKER_SSHAGENT="-v $SSH_AUTH_SOCK:$SSH_AUTH_SOCK -e SSH_AUTH_SOCK"

Creating a development container
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Build image, create container and start it::

    docker build --ssh default --target devel_shell -t libpvarki:devel_shell .
    docker create --name libpvarki_devel -v `pwd`":/app" -it `echo $DOCKER_SSHAGENT` libpvarki:devel_shell
    docker start -i libpvarki_devel

pre-commit considerations
^^^^^^^^^^^^^^^^^^^^^^^^^

If working in Docker instead of native env you need to run the pre-commit checks in docker too::

    docker exec -i libpvarki_devel /bin/bash -c "pre-commit install"
    docker exec -i libpvarki_devel /bin/bash -c "pre-commit run --all-files"

You need to have the container running, see above. Or alternatively use the docker run syntax but using
the running container is faster::

    docker run --rm -it -v `pwd`":/app" libpvarki:devel_shell -c "pre-commit run --all-files"

Test suite
^^^^^^^^^^

You can use the devel shell to run py.test when doing development, for CI use
the "tox" target in the Dockerfile::

    docker build --ssh default --target tox -t libpvarki:tox .
    docker run --rm -it -v `pwd`":/app" `echo $DOCKER_SSHAGENT` libpvarki:tox

## Development

TLDR:

- Create and activate a Python 3.8 virtualenv (assuming virtualenvwrapper)::

    mkvirtualenv -p `which python3.8` my_virtualenv

- change to a branch::

    git checkout -b my_branch

- install Poetry: https://python-poetry.org/docs/#installation
- Install project deps and pre-commit hooks::

    poetry install
    pre-commit install
    pre-commit run --all-files

- Ready to go.

Remember to activate your virtualenv whenever working on the repo, this is needed
because pylint and mypy pre-commit hooks use the "system" python for now (because reasons).
