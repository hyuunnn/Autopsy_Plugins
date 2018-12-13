import os
import json
from java.lang import System
from java.util.logging import Level
from org.sleuthkit.datamodel import TskData
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.report import GeneralReportModuleAdapter
from org.sleuthkit.autopsy.report.ReportProgressPanel import ReportStatus
from org.sleuthkit.autopsy.casemodule.services import FileManager
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute

class AutopsyReportModule(GeneralReportModuleAdapter):

    moduleName = "HWP Report (JSON)"

    def __init__(self):
        self._logger = Logger.getLogger(self.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def getName(self):
        return self.moduleName

    def getDescription(self):
        return "HWP Report (JSON)"

    def getRelativeFilePath(self):
        return "HWP_result.json"

    def getConfigurationPanel(self): # GUI Option
        pass

    ## https://stackoverflow.com/questions/8733233/filtering-out-certain-bytes-in-python/8735509
    def valid_xml_char_ordinal(self, c):
        codepoint = ord(c)
        # conditions ordered by presumed frequency
        return (
            0x20 <= codepoint <= 0xD7FF or
            codepoint in (0x9, 0xA, 0xD) or
            0xE000 <= codepoint <= 0xFFFD or
            0x10000 <= codepoint <= 0x10FFFF
            )

    def generateReport(self, baseReportDir, progressBar):
        result = []
        skCase = Case.getCurrentCase().getSleuthkitCase()

        json_fileName = os.path.join(baseReportDir, self.getRelativeFilePath())
        hwp_data = skCase.getBlackboardArtifacts("TSK_HWP_DATA")

        progressBar.setIndeterminate(False)
        progressBar.start()
        progressBar.setMaximumProgress(len(hwp_data))

        for artifact in hwp_data:
            attributes = artifact.getAttributes()
            data_dict = {}
            for attribute in attributes:
                data_dict[attribute.getAttributeType().displayName] = ''.join(c for c in attribute.getDisplayString() if self.valid_xml_char_ordinal(c))
            progressBar.increment()
            result.append(data_dict)
            
        with open(json_fileName, 'w') as outfile:
            json.dump(result, outfile)

        Case.getCurrentCase().addReport(json_fileName, self.moduleName, "HWP Report (JSON)")
        progressBar.increment()
        progressBar.complete(ReportStatus.COMPLETE)