import json


class Logger(object):
    """
        This handles logging of messages to wherever we want them.

        Instructions:
            When instantiating a new logger you import logger, then instantiate with
            the namespace for the logs, and the log level. Optional levels are
            info - will show all log messages
            warning - will show warnings and up
            error - will only show errors and critical messages

            There is not a critical log level because encountered errors should
            almost always be logged.

            The reset_ns and reset_log_level flags are used to change the current
            namespace or log level during execution

        Example:
            input:
                from Logger import logger

                my_log = new Logger('TEST_NAMESPACE', log_level='INFO')
                my_log.info('information message')
            output:
                INFO: TEST_NAMESPACE: information message
    """
    class __Logger(object):
        log_levels = {
            'DEBUG': ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
            'INFO': ['INFO', 'WARNING', 'ERROR', 'CRITICAL'],
            'WARNING': ['WARNING', 'ERROR', 'CRITICAL'],
            'ERROR': ['ERROR', 'CRITICAL']
        }

        def __init__(self, namespace, log_level):
            self.namespace = namespace
            self.log_level = log_level

        @property
        def log_level(self):
            return self._log_level

        @log_level.setter
        def log_level(self, log_level):
            if log_level.upper() not in Logger.__Logger.log_levels:
                raise AttributeError('{} log_level does not exist. Valid values are (INFO, WARNING, ERROR)'.format(log_level))
            self._log_level = log_level.upper()


        def debug(self, message, metrics=None):
            """
                Log an info message

                Args:
                    message (str): The message you want to log for info
                    metrics (dict): Any dict information that contains values
                                    you want to be able to easily report on 
                                    with custom CloudWatch metrics.
            """
            Logger.__Logger.log_message(self, 'debug', message, metrics)


        def info(self, message, metrics=None):
            """
                Log an info message

                Args:
                    message (str): The message you want to log for info
                    metrics (dict): Any dict information that contains values
                                    you want to be able to easily report on 
                                    with custom CloudWatch metrics.
            """
            Logger.__Logger.log_message(self, 'info', message, metrics)


        def warning(self, message, metrics=None):
            """
                Log a warning message

                Args:
                    message (str): The message you want to log for a warning
                    metrics (dict): Any dict information that contains values
                                    you want to be able to easily report on 
                                    with custom CloudWatch metrics.
            """
            Logger.__Logger.log_message(self, 'warning', message, metrics)


        def error(self, message, metrics=None):
            """
                Log an error message

                Args:
                    message (str): The message you want to log for an error
                    metrics (dict): Any dict information that contains values
                                    you want to be able to easily report on 
                                    with custom CloudWatch metrics.
            """
            Logger.__Logger.log_message(self, 'error', message, metrics)


        def critical(self, message, metrics=None):
            """
                Log a critical message

                Args:
                    message (str): The message you want to log for a critical issue
                    metrics (dict): Any dict information that contains values
                                    you want to be able to easily report on 
                                    with custom CloudWatch metrics.
            """
            Logger.__Logger.log_message(self, 'critical', message, metrics)


        def log_message(self, log_type, message, metrics=None):
            """
                This handles the logging of the different message types.

                Args:
                    log_type (str): The type of log to print.
                    message (str): The message you want to log for a critical issue
                    metrics (dict): Any dict information that contains values
                                    you want to be able to easily report on 
                                    with custom CloudWatch metrics.
            """
            if log_type.upper() in Logger.__Logger.log_levels[self.log_level]:
                message_dict = {
                    "type": log_type.upper(),
                    "namespace": self.namespace,
                    "message": str(message)
                }

                if metrics is not None:
                    message_dict["metrics"] = metrics

                message_json = json.dumps(message_dict)

                print(message_json)

    instance = None

    def __new__(cls, namespace, reset_ns=False, log_level='ERROR', reset_log_level=False):
        if not Logger.instance:
            Logger.instance = Logger.__Logger(namespace, log_level=log_level)
        else:
            if reset_ns:
                Logger.instance.namespace = namespace
            if reset_log_level:
                Logger.instance.log_level = log_level

        return Logger.instance
