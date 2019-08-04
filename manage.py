import os
import sys
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

from flask_script import (
    Manager,
    Server,
)

from application import create_app


app = create_app('default')
manager = Manager(app)

manager.add_command("runserver", Server(
    use_debugger=True,
    use_reloader=True,
    host=os.getenv('IP', '127.0.0.1'),
    port=int(os.getenv('PORT', 5000)))
)


if __name__ == "__main__":
    manager.run()
