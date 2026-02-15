from setuptools import setup
from setuptools.command.build_py import build_py
import subprocess
import sys


class BuildPyCommand(build_py):
	"""Custom build command that runs ruff before building."""

	def run(self):
		try:
			print('Running ruff check...')
			subprocess.check_call(['ruff', 'check'])
			print('Running ruff format check...')
			subprocess.check_call(['ruff', 'format'])
		except subprocess.CalledProcessError as e:
			print(f'Linting failed with exit code {e.returncode}. Aborting build.')
			sys.exit(e.returncode)
		except FileNotFoundError:
			print('Error: ruff not found. Please ensure ruff is installed.')
			sys.exit(1)

		super().run()


if __name__ == '__main__':
	setup(
		cmdclass={
			'build_py': BuildPyCommand,
		}
	)
