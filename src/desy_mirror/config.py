import dataclasses as dc
import logging

from wipac_dev_tools import from_environment_as_dataclass

@dc.dataclass(frozen=True)
class EnvConfig:
    OPENID_CLIENT_ID: str
    OPENID_CLIENT_SECRET: str = ''
    OPENID_URL: str = 'https://keycloak.icecube.wisc.edu/auth/realms/IceCube'
    OPENID_SCOPES: str = ''

    SRC_DIRECTORY: str = '/data/exp/IceCube/2025/filtered/level2'
    DEST_HOST: str = 'https://globe-door.ifh.de:2880'
    #DEST_PREFIX: str = '/pnfs/ifh.de/acs/icecube/archive'
    DEST_PREFIX: str = '/pnfs/ifh.de/acs/icecube/diskonly'

    MAX_PARALLEL: int = 100
    TIMEOUT_SECS: int = 600
    RETRIES: int = 3

    CI_TEST: bool = False
    LOG_LEVEL: str = 'INFO'

    def __post_init__(self) -> None:
        object.__setattr__(self, 'LOG_LEVEL', self.LOG_LEVEL.upper())  # b/c frozen

ENV = from_environment_as_dataclass(EnvConfig, collection_sep=',')


def config_logging():
    # handle logging
    setlevel = {
        'CRITICAL': logging.CRITICAL,  # execution cannot continue
        'FATAL': logging.CRITICAL,
        'ERROR': logging.ERROR,  # something is wrong, but try to continue
        'WARNING': logging.WARNING,  # non-ideal behavior, important event
        'WARN': logging.WARNING,
        'INFO': logging.INFO,  # initial debug information
        'DEBUG': logging.DEBUG  # the things no one wants to see
    }

    if ENV.LOG_LEVEL not in setlevel:
        raise Exception('LOG_LEVEL is not a proper log level')
    logformat = '%(asctime)s %(levelname)s %(name)s %(module)s:%(lineno)s - %(message)s'
    logging.basicConfig(format=logformat, level=setlevel[ENV.LOG_LEVEL])
