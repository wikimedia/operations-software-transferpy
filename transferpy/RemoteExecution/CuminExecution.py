"""
CuminExecution is the implementation, using Cumin as a backend, of the RemoteExecution
interface- a generic but simple abstraction of a straightforward api to execute remote
commands on hosts, but hiding the complexity of the Cumin configuration details.
"""

from multiprocessing import Pipe, Process

import cumin  # type: ignore
from cumin import query, transport, transports  # type: ignore
from cumin.transports.clustershell import NullReporter

from transferpy.RemoteExecution.RemoteExecution import CommandReturn, RemoteExecution


# TODO: Refactor with the one on ParamikoExecution or find a better approach
def run_subprocess(host, command, input_pipe):
    """
    Runs the given command in a subprocess with the given input stream.
    """
    e = CuminExecution()
    result = e.run(host, command)
    input_pipe.send(result)


class CuminExecution(RemoteExecution):
    """
    RemoteExecution implementation using Cumin
    """

    def __init__(self, options={}):
        self._config = None
        self.options = options

    @property
    def config(self):
        """
        Returns the Cumin configuration, and creates if it was empty.
        """
        if not self._config:
            self._config = cumin.Config()

        return self._config

    def format_command(self, command):
        """
        If a command is received as a string, it leaves it unchanged, but if it is a list,
        it generates a string with the list elements (strings) joined with a space.
        """
        if isinstance(command, str):
            return command
        return " ".join(command)

    def run(self, host, command):
        """
        Runs syncronously a simple command on the given remote host. It waits for it to finish
        before continuing, and returns a CommandReturn object with the return_code property based
        on the exit code of that command, and a result, with the standard output.
        """
        hosts = query.Query(self.config).execute(host)
        if not hosts:
            return CommandReturn(1, None, "host is wrong or does not match rules")
        target = transports.Target(hosts)
        worker = transport.Transport.new(self.config, target)
        worker.commands = [self.format_command(command)]
        worker.handler = "sync"

        worker.progress_bars = False
        # If verbose is false, suppress stdout and stderr of Cumin.
        if not self.options.get("verbose", False):
            worker.reporter = NullReporter

        return_code = worker.execute()

        for nodes, output in worker.get_results():
            if host in nodes:
                result = str(bytes(output), "utf-8")
                return CommandReturn(return_code, result, None)

        return CommandReturn(return_code, None, None)

    def start_job(self, host, command):
        """
        Runs a command asyncronously on a given host, starting it and returning immediately with
        a dictionary with a key "process", with the job id, and a key "pipe", with a stream for
        the standard output.
        """
        output_pipe, input_pipe = Pipe()
        job = Process(target=run_subprocess, args=(host, command, input_pipe))
        job.start()
        input_pipe.close()
        return {"process": job, "pipe": output_pipe}

    def monitor_job(self, host, job):
        """
        Given a host and a job id as returned from start_job, it returns immediately with
        a null CommandReturn (None in all its properties) if the job is still running, otherwise
        it returns and closes the output stream.
        """
        if job["process"].is_alive():
            return CommandReturn(None, None, None)
        result = job["pipe"].recv()
        job["pipe"].close()
        return result

    def kill_job(self, host, job):
        """
        Given a host and a job id as returned from start_job, if terminates the job.
        """
        if job["process"].is_alive():
            job["process"].terminate()

    def wait_job(self, host, job):
        """
        Given a host and a job id, it gets syncronously blocked, waiting for its termination, and
        when it finishes it returns and closes the output stream.
        """
        job["process"].join()
        result = job["pipe"].recv()
        job["pipe"].close()
        return result
