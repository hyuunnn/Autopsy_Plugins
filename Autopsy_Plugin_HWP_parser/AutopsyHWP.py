import jarray
import inspect
import os
import hashlib

from javax.swing import JCheckBox
from javax.swing import BoxLayout
from javax.swing import JButton
from javax.swing import ButtonGroup
from javax.swing import JComboBox
#from javax.swing import JRadioButton
from javax.swing import JList
from javax.swing import JTextArea
from javax.swing import JTextField
from javax.swing import JLabel
from java.awt import GridLayout
from java.awt import GridBagLayout
from java.awt import GridBagConstraints
from javax.swing import JPanel
from javax.swing import JScrollPane
from javax.swing import JFileChooser
from javax.swing.filechooser import FileNameExtensionFilter

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
from org.sleuthkit.autopsy.ingest import IngestModuleIngestJobSettings
from org.sleuthkit.autopsy.ingest import IngestModuleIngestJobSettingsPanel
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.ingest import ModuleDataEvent
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.datamodel import ContentUtils
from org.sleuthkit.autopsy.casemodule.services import Services
from org.sleuthkit.autopsy.casemodule.services import FileManager
from java.lang import IllegalArgumentException

import olefile
from hwp import hwp_parser

class HWPIngestModuleFactory(IngestModuleFactoryAdapter):
    def __init__(self):
        self.settings = None

    moduleName = "HWP Parser"

    def getModuleDisplayName(self):
        return self.moduleName

    def getModuleDescription(self):
        return "HWP Parser"

    def getModuleVersionNumber(self):
        return "1.0"

    def getDefaultIngestJobSettings(self):
        return HWPIngestModuleWithUISettings()

    def hasIngestJobSettingsPanel(self):
        return True

    def getIngestJobSettingsPanel(self, settings):
        if not isinstance(settings, HWPIngestModuleWithUISettings):
            raise IllegalArgumentException("Expected settings argument to be instanceof SampleIngestModuleSettings")
        self.settings = settings
        return HWPIngestModuleWithUISettingsPanel(self.settings)

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return HWPIngestModule(self.settings)

class HWPIngestModule(DataSourceIngestModule):

    _logger = Logger.getLogger(HWPIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def __init__(self, settings):
        self.context = None
        self.local_settings = settings
        self.eps_check = 0
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
        pass

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

            try:
                attID = skCase.addArtifactAttributeType("TSK_HWP_EPS_CHECK", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "EPS_Check")
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
        EPSDirectory = os.path.join(Case.getCurrentCase().getTempDirectory(),"EPS Files")
        try:
            os.mkdir(HWPDirectory)
        except:
            pass

        try:
            os.mkdir(EPSDirectory)
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

            if not sample_data[:4] == '\xd0\xcf\x11\xe0':
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
                            HWPIngestModuleFactory.moduleName, "This is not a HWPv5 File."))
                continue

            try:
                hwp = hwp_parser(HWPPath)
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
                continue
            
            HwpSummaryInfo_data = hwp.extract_HwpSummaryInfo()
            FileHeader_data = hwp.extract_FileHeader()

            if self.local_settings.checkbox_getFlag():
                eps_data = hwp.extract_eps()
                if eps_data != []:
                    self.eps_check = 1
                    filepath = os.path.join(EPSDirectory, os.path.splitext(unicode(file.getName()))[0])
                    try:
                        os.mkdir(filepath)
                    except:
                        pass
                        
                    for name, data in eps_data:
                        f = open(os.path.join(filepath, name), "wb")
                        f.write(data)
                        f.close()
                else:
                    self.eps_check = 0

            art = file.newArtifact(artHwpId)
            art.addAttribute(BlackboardAttribute(skCase.getAttributeType("TSK_HWP_FILENAME"), 
                        HWPIngestModuleFactory.moduleName, unicode(file.getName())))
            art.addAttribute(BlackboardAttribute(skCase.getAttributeType("TSK_HWP_MD5"), 
                        HWPIngestModuleFactory.moduleName, md5))
            art.addAttribute(BlackboardAttribute(skCase.getAttributeType("TSK_HWP_SHA1"), 
                        HWPIngestModuleFactory.moduleName, sha1))
            art.addAttribute(BlackboardAttribute(skCase.getAttributeType("TSK_HWP_SHA256"), 
                        HWPIngestModuleFactory.moduleName, sha256))
            art.addAttribute(BlackboardAttribute(skCase.getAttributeType("TSK_HWP_EPS_CHECK"), 
                        HWPIngestModuleFactory.moduleName, str(self.eps_check)))

            if HwpSummaryInfo_data != None:
                for Hwpinfo in HwpSummaryInfo_data:
                    art.addAttribute(BlackboardAttribute(skCase.getAttributeType("TSK_"+Hwpinfo['name']), 
                                HWPIngestModuleFactory.moduleName, Hwpinfo['data']))

            if FileHeader_data != None:
                art.addAttribute(BlackboardAttribute(skCase.getAttributeType("TSK_HWPHeaderVersion"), 
                            HWPIngestModuleFactory.moduleName, str(FileHeader_data['version'])))
                art.addAttribute(BlackboardAttribute(skCase.getAttributeType("TSK_HWPHeaderFlags"), 
                            HWPIngestModuleFactory.moduleName, str(FileHeader_data['flags'])))

            progressBar.progress(fileCount)

        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
            "HWP Parser", "Found %d files" % fileCount)
        IngestServices.getInstance().postMessage(message)

        return IngestModule.ProcessResult.OK

class HWPIngestModuleWithUISettings(IngestModuleIngestJobSettings):
    serialVersionUID = 1L

    def __init__(self):
        self.checkbox_Flag = False

    def getVersionNumber(self):
        return serialVersionUID

    # TODO: Define getters and settings for data you want to store from UI
    def checkbox_getFlag(self):
        return self.checkbox_Flag

    def checkbox_setFlag(self, flag):
        self.checkbox_Flag = flag
        
# UI that is shown to user for each ingest job so they can configure the job.
# TODO: Rename this
class HWPIngestModuleWithUISettingsPanel(IngestModuleIngestJobSettingsPanel):
    def __init__(self, settings):
        self.local_settings = settings
        self.initComponents()
        self.customizeComponents()

    def checkBoxEvent(self, event):
        if self.checkbox.isSelected():
            self.local_settings.checkbox_setFlag(True)
        else:
            self.local_settings.checkbox_setFlag(False)

    def initComponents(self):
        self.panel0 = JPanel()
        self.checkbox = JCheckBox("Extract EPS", actionPerformed=self.checkBoxEvent)
        self.panel0.add(self.checkbox)
        self.add(self.panel0)

    def customizeComponents(self):
        self.checkbox.setSelected(self.local_settings.checkbox_getFlag())

    def getSettings(self):
        return self.local_settings