import jarray
import inspect
import os
from subprocess import Popen, PIPE

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

class YARAIngestModuleFactory(IngestModuleFactoryAdapter):
    def __init__(self):
        self.settings = None

    moduleName = "Yara"

    def getModuleDisplayName(self):
        return self.moduleName

    def getModuleDescription(self):
        return "Yara"

    def getModuleVersionNumber(self):
        return "1.0"

    def getDefaultIngestJobSettings(self):
        return YARAIngestModuleWithUISettings()

    def hasIngestJobSettingsPanel(self):
        return True

    def getIngestJobSettingsPanel(self, settings):
        if not isinstance(settings, YARAIngestModuleWithUISettings):
            raise IllegalArgumentException("Expected settings argument to be instanceof SampleIngestModuleSettings")
        self.settings = settings
        return YARAIngestModuleWithUISettingsPanel(self.settings)

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return YARAIngestModule(self.settings)

class YARAIngestModule(DataSourceIngestModule):

    _logger = Logger.getLogger(YARAIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def __init__(self, settings):
        self.context = None
        self.local_settings = settings

    def startUp(self, context):
        self.context = context
        pass

    def process(self, dataSource, progressBar):
        progressBar.switchToIndeterminate()
        skCase = Case.getCurrentCase().getSleuthkitCase()
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        
        yara_exe = os.path.join(os.path.dirname(os.path.abspath(__file__)), "yara64.exe")
        Extension = self.local_settings.Extension_getText()
        YaraPath = self.local_settings.YaraPath_getText()
        files = fileManager.findFiles(dataSource, "%" + Extension) 
        numFiles = len(files)
        progressBar.switchToDeterminate(numFiles)
        fileCount = 0

        if numFiles > 0:
            try:
                attID = skCase.addArtifactAttributeType("TSK_YARA_FILENAME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "filename")
            except:
                pass

            try:
                attID = skCase.addArtifactAttributeType("TSK_YARA_YARAPATH", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Yarapath")
            except:
                pass

            try:
                attID = skCase.addArtifactAttributeType("TSK_YARA_RULENAME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Rulename")
            except:
                pass
            
            try:
                attID = skCase.addArtifactAttributeType("TSK_YARA_FILEPATH", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Filepath")
            except:
                pass

            try:
                attID = skCase.addArtifactAttributeType("TSK_YARA_ERROR", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "ERROR")
            except:
                pass

            try:
                artID_art = skCase.addArtifactType("TSK_YARA_DATA", "YARA Analysis")
            except:
                pass

        FILEDirectory = os.path.join(Case.getCurrentCase().getTempDirectory(),"YARA Files")
        try:
            os.mkdir(FILEDirectory)
        except:
            pass

        for file in files:
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            self.log(Level.INFO, "Processing file: " + file.getName())
            fileCount += 1

            FILEPath = os.path.join(FILEDirectory, unicode(file.getName()))
            ContentUtils.writeToFile(file, File(FILEPath))

            artYARAId = skCase.getArtifactTypeID("TSK_YARA_DATA")

            pipe = Popen([yara_exe, YaraPath, os.path.join(FILEDirectory, unicode(file.getName()))], stdout=PIPE, stderr=PIPE)
            out_text = pipe.communicate()[0]
            if out_text != b"":
                YaraResult = out_text.rstrip()

                rulename = YaraResult.split(b" ")[0]
                filepath = YaraResult.split(b" ")[1]

                art = file.newArtifact(artYARAId)
                art.addAttribute(BlackboardAttribute(skCase.getAttributeType("TSK_YARA_FILENAME"), 
                            YARAIngestModuleFactory.moduleName, unicode(file.getName())))
                art.addAttribute(BlackboardAttribute(skCase.getAttributeType("TSK_YARA_YARAPATH"), 
                            YARAIngestModuleFactory.moduleName, YaraPath))
                art.addAttribute(BlackboardAttribute(skCase.getAttributeType("TSK_YARA_RULENAME"), 
                            YARAIngestModuleFactory.moduleName, rulename))
                art.addAttribute(BlackboardAttribute(skCase.getAttributeType("TSK_YARA_FILEPATH"), 
                            YARAIngestModuleFactory.moduleName, filepath))
            else:
                art = file.newArtifact(artYARAId)
                art.addAttribute(BlackboardAttribute(skCase.getAttributeType("TSK_YARA_FILENAME"), 
                            YARAIngestModuleFactory.moduleName, unicode(file.getName())))
                art.addAttribute(BlackboardAttribute(skCase.getAttributeType("TSK_YARA_YARAPATH"), 
                                YARAIngestModuleFactory.moduleName, YaraPath))
                art.addAttribute(BlackboardAttribute(skCase.getAttributeType("TSK_YARA_ERROR"), 
                            YARAIngestModuleFactory.moduleName, "Not Detected"))

            progressBar.progress(fileCount)

        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
            "Yara", "Found %d files" % fileCount)
        IngestServices.getInstance().postMessage(message)

        return IngestModule.ProcessResult.OK

class YARAIngestModuleWithUISettings(IngestModuleIngestJobSettings):
    serialVersionUID = 1L

    def __init__(self):
        self.Extension = ""
        self.YaraPath = ""

    def getVersionNumber(self):
        return serialVersionUID

    # TODO: Define getters and settings for data you want to store from UI
    def Extension_getText(self):
        return self.Extension

    def Extension_setText(self, data):
        self.Extension = data

    def YaraPath_getText(self):
        return self.YaraPath

    def YaraPath_setText(self, data):
        self.YaraPath = data
        
# UI that is shown to user for each ingest job so they can configure the job.
# TODO: Rename this
class YARAIngestModuleWithUISettingsPanel(IngestModuleIngestJobSettingsPanel):
    def __init__(self, settings):
        self.local_settings = settings
        self.initComponents()
        self.customizeComponents()

    def buttonEvent(self, event):
        self.local_settings.YaraPath_setText(self.textfield_2.getText())
        self.local_settings.Extension_setText(self.textfield_3.getText())

    def initComponents(self):
        self.panel0 = JPanel()
        self.gbPanel0 = GridBagLayout()
        self.gbcPanel0 = GridBagConstraints()
        self.panel0.setLayout(self.gbPanel0)

        self.Label_2 = JLabel("Yara Path : ")
        self.Label_2.setEnabled(True)
        self.gbcPanel0.gridx = 1
        self.gbcPanel0.gridy = 6
        self.gbPanel0.setConstraints(self.Label_2, self.gbcPanel0)
        self.panel0.add(self.Label_2)

        self.textfield_2 = JTextField(15)
        self.gbcPanel0.gridx = 2
        self.gbcPanel0.gridy = 6
        self.gbPanel0.setConstraints(self.textfield_2, self.gbcPanel0)
        self.panel0.add(self.textfield_2)

        self.Label_3 = JLabel("Extension : ")
        self.Label_3.setEnabled(True)
        self.gbcPanel0.gridx = 1
        self.gbcPanel0.gridy = 8
        self.gbPanel0.setConstraints(self.Label_3, self.gbcPanel0)
        self.panel0.add(self.Label_3)

        self.textfield_3 = JTextField(15)
        self.gbcPanel0.gridx = 2
        self.gbcPanel0.gridy = 8
        self.gbPanel0.setConstraints(self.textfield_3, self.gbcPanel0)
        self.panel0.add(self.textfield_3)

        self.button = JButton("Enter", actionPerformed=self.buttonEvent)
        self.gbcPanel0.gridx = 1
        self.gbcPanel0.gridy = 10
        self.panel0.add(self.button)

        self.add(self.panel0)

    def customizeComponents(self):
        pass

    def getSettings(self):
        return self.local_settings