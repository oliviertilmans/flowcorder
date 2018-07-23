"""flowcorder -- Set of functions/modules to  instrument end hosts."""
import logging
# Basic config if nothing else is set
logging.basicConfig(format='%(levelname)8s-%(name)s> %(message)s',
                    level=logging.DEBUG)


# Debug options that are available through components.
DEBUG_OPTIONS = set()
# Global debug flag
DEBUG = set()
# Daemons should run as long as IS_RUNNING is True
IS_RUNNING = True
