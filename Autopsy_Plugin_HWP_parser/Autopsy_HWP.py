import jarray
import inspect
import os
import hashlib

from java.util.logging import Level
from java.io import File
from org.sleuthkit.datamodel import SleuthkitCase
from org.sleuthkit.datamodel import AbstractFile
from org.sleuthkit.datamodel import ReadContentInputStream
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest.IngestModule import IngestModuleException
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.ingest import ModuleDataEvent
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.datamodel import ContentUtils
from org.sleuthkit.autopsy.casemodule.services import Services
from org.sleuthkit.autopsy.casemodule.services import FileManager

import olefile
from hwp import hwp_parser

class HWPIngestModuleFactory(IngestModuleFactoryAdapter):

    moduleName = "HWP Parser"

    def getModuleDisplayName(self):
        return self.moduleName

    def getModuleDescription(self):
        return "HWP Parser"

    def getModuleVersionNumber(self):
        return "1.0"

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return HWPIngestModule()

class HWPIngestModule(DataSourceIngestModule):

    _logger = Logger.getLogger(HWPIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def __init__(self):
        self.context = None
        self.SUMMARY_INFORMATION_PROPERTIES = [
            dict(id=0x02, name='PIDSI_TITLE', title='Title'),
            dict(id=0x03, name='PIDSI_SUBJECT', title='Subject'),
            dict(id=0x04, name='PIDSI_AUTHOR', title='Author'),
            dict(id=0x05, name='PIDSI_KEYWORDS', title='Keywords'),
            dict(id=0x06, name='PIDSI_COMMENTS', title='Comments'),
            dict(id=0x07, name='PIDSI_TEMPLATE', title='Templates'),
            dict(id=0x08, name='PIDSI_LASTAUTHOR', title='Last Saved By'),
            dict(id=0x09, name='PIDSI_REVNUMBER', title='Revision Number'),
            dict(id=0x0a, name='PIDSI_EDITTIME', title='Total Editing Time'),
            dict(id=0x0b, name='PIDSI_LASTPRINTED', title='Last Printed'),
            dict(id=0x0c, name='PIDSI_CREATE_DTM', title='Create Time/Data'),
            dict(id=0x0d, name='PIDSI_LASTSAVE_DTM', title='Last saved Time/Data'),
            dict(id=0x0e, name='PIDSI_PAGECOUNT', title='Number of Pages'),
            dict(id=0x0f, name='PIDSI_WORDCOUNT', title='Number of Words'),
            dict(id=0x10, name='PIDSI_CHARCOUNT', title='Number of Characters'),
            dict(id=0x11, name='PIDSI_THUMBNAIL', title='Thumbnail'),
            dict(id=0x12, name='PIDSI_APPNAME', title='Name of Creating Application'),
            dict(id=0x13, name='PIDSI_SECURITY', title='Security'),
        ]

    def startUp(self, context):
        self.context = context

    def process(self, dataSource, progressBar):
        progressBar.switchToIndeterminate()
        skCase = Case.getCurrentCase().getSleuthkitCase()
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        files = fileManager.findFiles(dataSource, "%.hwp")
        numFiles = len(files)
        progressBar.switchToDeterminate(numFiles)
        fileCount = 0

        if numFiles > 0:
            try:
                attID = skCase.addArtifactAttributeType("TSK_HWP_FILENAME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Filename")
            except:
                pass
            
            try:
                attID = skCase.addArtifactAttributeType("TSK_HWP_MD5", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "MD5")
            except:
                pass

            try:
                attID = skCase.addArtifactAttributeType("TSK_HWP_SHA1", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "SHA1")
            except:
                pass

            try:
                attID = skCase.addArtifactAttributeType("TSK_HWP_SHA256", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "SHA256")
            except:
                pass

            try:
                attID = skCase.addArtifactAttributeType("TSK_HWP_ERROR", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "ERROR")
            except:
                pass

            for artifact in self.SUMMARY_INFORMATION_PROPERTIES:
                try:
                    attID = skCase.addArtifactAttributeType("TSK_"+artifact['name'], BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, artifact['title'])
                except:
                    pass

            try:
                attID = skCase.addArtifactAttributeType("TSK_HWPHeaderVersion", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "HWPHeaderVersion")
            except:
                pass

            try:
                attID = skCase.addArtifactAttributeType("TSK_HWPHeaderFlags", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "HWPHeaderFlags")
            except:
                pass

            try:
                artID_art = skCase.addArtifactType("TSK_HWP_DATA", "HWP Analysis")
            except:
                pass

        HWPDirectory = os.path.join(Case.getCurrentCase().getTempDirectory(),"HWP Files")
        try:
            os.mkdir(HWPDirectory)
        except:
            pass

        for file in files:
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            self.log(Level.INFO, "Processing file: " + file.getName())
            fileCount += 1

            HWPPath = os.path.join(HWPDirectory, unicode(file.getName()))
            ContentUtils.writeToFile(file, File(HWPPath))

            sample = open(HWPPath,"rb")
            sample_data = sample.read()
            sample.close()
            md5 = hashlib.md5(sample_data).hexdigest()
            sha1 = hashlib.sha1(sample_data).hexdigest()
            sha256 = hashlib.sha256(sample_data).hexdigest()
            artHwpId = skCase.getArtifactTypeID("TSK_HWP_DATA")

            try:
                hwp = hwp_parser(HWPPath)
                HwpSummaryInfo_data = hwp.extract_HwpSummaryInfo()
                FileHeader_data = hwp.extract_FileHeader()
                #eps_data = hwp.extract_eps()

                art = file.newArtifact(artHwpId)
                art.addAttribute(BlackboardAttribute(skCase.getAttributeType("TSK_HWP_FILENAME"), 
                            HWPIngestModuleFactory.moduleName, unicode(file.getName())))
                art.addAttribute(BlackboardAttribute(skCase.getAttributeType("TSK_HWP_MD5"), 
                            HWPIngestModuleFactory.moduleName, md5))
                art.addAttribute(BlackboardAttribute(skCase.getAttributeType("TSK_HWP_SHA1"), 
                            HWPIngestModuleFactory.moduleName, sha1))
                art.addAttribute(BlackboardAttribute(skCase.getAttributeType("TSK_HWP_SHA256"), 
                            HWPIngestModuleFactory.moduleName, sha256))

                if HwpSummaryInfo_data != None:
                    for Hwpinfo in HwpSummaryInfo_data:
                        art.addAttribute(BlackboardAttribute(skCase.getAttributeType("TSK_"+Hwpinfo['name']), 
                                    HWPIngestModuleFactory.moduleName, Hwpinfo['data']))

                if FileHeader_data != None:
                    art.addAttribute(BlackboardAttribute(skCase.getAttributeType("TSK_HWPHeaderVersion"), 
                                HWPIngestModuleFactory.moduleName, str(FileHeader_data['version'])))
                    art.addAttribute(BlackboardAttribute(skCase.getAttributeType("TSK_HWPHeaderFlags"), 
                                HWPIngestModuleFactory.moduleName, str(FileHeader_data['flags'])))
                
            except IOError: # HWP File Error
                art = file.newArtifact(artHwpId)
                art.addAttribute(BlackboardAttribute(skCase.getAttributeType("TSK_HWP_FILENAME"), 
                            HWPIngestModuleFactory.moduleName, unicode(file.getName())))
                art.addAttribute(BlackboardAttribute(skCase.getAttributeType("TSK_HWP_MD5"), 
                            HWPIngestModuleFactory.moduleName, md5))
                art.addAttribute(BlackboardAttribute(skCase.getAttributeType("TSK_HWP_SHA1"), 
                            HWPIngestModuleFactory.moduleName, sha1))
                art.addAttribute(BlackboardAttribute(skCase.getAttributeType("TSK_HWP_SHA256"), 
                            HWPIngestModuleFactory.moduleName, sha256))
                art.addAttribute(BlackboardAttribute(skCase.getAttributeType("TSK_HWP_ERROR"), 
                            HWPIngestModuleFactory.moduleName, "HWP File Error"))

            progressBar.progress(fileCount)

        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
            "HWP Parser", "Found %d files" % fileCount)
        IngestServices.getInstance().postMessage(message)

        return IngestModule.ProcessResult.OK