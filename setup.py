from setuptools import setup, find_packages

setup(
  name='pywmi-wbem',
  version='0.3.1',
  description='Library for WMI interaction and Nagios checks',
  author='David Voit, Alexander Lex',
  author_email='david.voit@ams-osram.com, alexander.lex@ams-osram.com',

  classifiers=[
    'Development Status :: 4 - Beta',
    'Intended Audience :: Developers',
    'Topic :: System :: Monitoring',
    'Programming Language :: Python :: 3',
  ],

  install_requires=[
    'requests',
    'gssapi',
    'pytz',
    'lxml'
  ],

  packages=find_packages('src'),
  package_dir={'':'src'},

  scripts=[
    'nagios_checks/check_disk_wbem',
    'nagios_checks/check_file_wbem',
    'nagios_checks/check_load_wbem',
    'nagios_checks/check_memory_wbem',
    'nagios_checks/check_process_wbem',
    'nagios_checks/check_remote_ping_wbem',
    'nagios_checks/check_smart_wbem',
    'nagios_checks/check_swap_wbem',
    'nagios_checks/check_win_update_wbem',
    'nagios_checks/check_win_task_wbem', 
    'nagios_checks/check_directory_wbem' 
 ]
)
