import jarray
import inspect
import os
import urllib
import urllib2
import json
from subprocess import Popen, PIPE

from javax.swing import JPanel
from javax.swing import JLabel
from javax.swing import JTextArea
from javax.swing import JTextField
from java.awt import GridLayout

from java.lang import Class
from java.lang import System
from java.sql  import DriverManager, SQLException
from java.util.logging import Level
from java.io import File
from org.sleuthkit.datamodel import TskData
from org.sleuthkit.datamodel import SleuthkitCase
from org.sleuthkit.datamodel import AbstractFile
from org.sleuthkit.datamodel import ReadContentInputStream
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest.IngestModule import IngestModuleException
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import FileIngestModule
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import IngestModuleIngestJobSettings
from org.sleuthkit.autopsy.ingest import IngestModuleIngestJobSettingsPanel
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.ingest import ModuleDataEvent
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.coreutils import PlatformUtil
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.casemodule.services import Services
from org.sleuthkit.autopsy.casemodule.services import FileManager
from org.sleuthkit.autopsy.datamodel import ContentUtils

class ExtractIngestModuleFactory(IngestModuleFactoryAdapter):

    moduleName = "Extension Extraction Tool"

    def getModuleDisplayName(self):
        return self.moduleName

    def getModuleDescription(self):
        return "This is Extension Extraction Tool"

    def getModuleVersionNumber(self):
        return "1.0"

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return ExtractDataSourceIngestModule()

class ExtractDataSourceIngestModule(DataSourceIngestModule):

    _logger = Logger.getLogger(ExtractIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def startUp(self, context):
        self.context = context
        self.report = open("C:\\users\\" + os.getenv("username") + "\\Desktop\\extension_result.txt","w")

    def process(self, dataSource, progressBar):

        progressBar.switchToIndeterminate()
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        extension_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "extension.txt")
        extension = open(extension_path, "r").read()
        files = fileManager.findFiles(dataSource, "%"+extension)
        numFiles = len(files)
        progressBar.switchToDeterminate(numFiles)
        fileCount = 0

        for file in files:
            fileCount += 1
            progressBar.progress(fileCount)
            md5hash = file.getMd5Hash()
            if not md5hash == None:
                md5 = md5hash
            else:
                md5 = ""

            self.report.write("Path : " + file.getUniquePath() + "\n" +
                              "Size : " + str(file.getSize()) + "\n" +  
                              "MD5 : " + md5 + "\n\n")

        self.report.write("fileCount : " + str(fileCount))
        self.report.close()

        return IngestModule.ProcessResult.OK