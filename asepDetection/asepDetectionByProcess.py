import re
from abc import ABC, abstractmethod

from volatility3.framework import interfaces, renderers, contexts, constants
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.symbols import mac
from volatility3.framework.objects import utility

from volatility3.plugins.mac import pslist, list_files

class AsepInterface (ABC):

        @abstractmethod
        def detect(self, source):
                pass

class MacAsep (AsepInterface):

        def __init__ (self, _asepName):

                self.asepName = _asepName
                self.asep_evidences = set ()

        def get_evidences (self):

                if not self.isAsepDetected():

                        self.asep_evidences.add((self.asepName, False, -1, "N/A", "N/A"))

                return self.asep_evidences

        def isAsepDetected (self):

                return len(self.asep_evidences) > 0

class AsepCron (MacAsep):

        def __init__ (self):

                super().__init__ ("Cron")

        def detect (self, task):

                if "cron" in utility.array_to_string(task.p_comm):
                        self.asep_evidences.add((self.asepName, True, task.p_pid, utility.array_to_string(task.p_comm), utility.array_to_string(task.p_pptr.p_comm)))

class AsepReopenedApps (MacAsep):

        def __init__ (self):

                super().__init__ ("Reopened Apps")

        def detect (self, task):

                if "loginwindow" in utility.array_to_string(task.p_comm):
                        self.asep_evidences.add((self.asepName, True, task.p_pid, utility.array_to_string(task.p_comm), utility.array_to_string(task.p_pptr.p_comm)))

class AsepKexts(MacAsep):

        def __init__(self):

                super().__init__("Kexts")

        def detect(self, task):

                if "kextd" in utility.array_to_string(task.p_comm):
                        self.asep_evidences.add((self.asepName, True, task.p_pid, utility.array_to_string(task.p_comm), utility.array_to_string(task.p_pptr.p_comm)))

class AsepDockTilePlugin(MacAsep):

        def __init__(self):

                super().__init__("Dock Tile Plugin")

        def detect(self, task):

                if "Dock" in utility.array_to_string(task.p_comm):
                        self.asep_evidences.add((self.asepName, True, task.p_pid, utility.array_to_string(task.p_comm), utility.array_to_string(task.p_pptr.p_comm)))

class AsepAuthPlugins(MacAsep):

        def __init__(self):

                super().__init__("Auth Plugins")

        def detect(self, task):

                if "securityd" in utility.array_to_string(task.p_comm):
                        self.asep_evidences.add((self.asepName, True, task.p_pid, utility.array_to_string(task.p_comm), utility.array_to_string(task.p_pptr.p_comm)))

class AsepLoginItems(MacAsep):

        def __init__(self):

                super().__init__("Login Items")

        def detect(self, task):

                if "loginwindow" in utility.array_to_string(task.p_comm):
                        self.asep_evidences.add((self.asepName, True, task.p_pid, utility.array_to_string(task.p_comm), utility.array_to_string(task.p_pptr.p_comm)))

class AsepSandboxedLoginApp(MacAsep):

        def __init__(self):

                super().__init__("Sandbox")

        def detect(self, task):

                if "sandboxd" in utility.array_to_string(task.p_comm):
                        self.asep_evidences.add((self.asepName, True, task.p_pid, utility.array_to_string(task.p_comm), utility.array_to_string(task.p_pptr.p_comm)))

class AsepLoginHooks(MacAsep):

        def __init__(self):

                super().__init__("Login Hooks")

        def detect(self, task):

                if "loginwindow" in utility.array_to_string(task.p_comm):
                        self.asep_evidences.add((self.asepName, True, task.p_pid, utility.array_to_string(task.p_comm), utility.array_to_string(task.p_pptr.p_comm)))

class AsepProfiles(MacAsep):

        def __init__(self):

                super().__init__("Profiles")

        def detect(self, task):

                if "profiles" in utility.array_to_string(task.p_comm):
                        self.asep_evidences.add((self.asepName, True, task.p_pid, utility.array_to_string(task.p_comm), utility.array_to_string(task.p_pptr.p_comm)))

class AsepAudioPlugin(MacAsep):

        def __init__(self):

                super().__init__("Audio Plugin")

        def detect(self, task):

                if "coreaudiod" in utility.array_to_string(task.p_comm):
                        self.asep_evidences.add((self.asepName, True, task.p_pid, utility.array_to_string(task.p_comm), utility.array_to_string(task.p_pptr.p_comm)))


class AsepSpotlight(MacAsep):

        def __init__(self):

                super().__init__("Spotlight")

        def detect(self, task):

                if "Spotlight" in utility.array_to_string(task.p_comm):
                        self.asep_evidences.add((self.asepName, True, task.p_pid, utility.array_to_string(task.p_comm), utility.array_to_string(task.p_pptr.p_comm)))

class AsepQuicklook(MacAsep):

        def __init__(self):

                super().__init__("Quicklook")

        def detect(self, task):

                if "quickl" in utility.array_to_string(task.p_comm):
                        self.asep_evidences.add((self.asepName, True, task.p_pid, utility.array_to_string(task.p_comm), utility.array_to_string(task.p_pptr.p_comm)))

class AsepScreenSaver(MacAsep):

        def __init__(self):

                super().__init__("Screen Saver")

        def detect(self, task):

                if "ScreenSaver" in utility.array_to_string(task.p_comm):
                        self.asep_evidences.add((self.asepName, True, task.p_pid, utility.array_to_string(task.p_comm), utility.array_to_string(task.p_pptr.p_comm)))

class AsepEmond(MacAsep):

        def __init__(self):

                super().__init__("Emond")

        def detect(self, task):

                if "emond" in utility.array_to_string(task.p_comm):
                        self.asep_evidences.add((self.asepName, True, task.p_pid, utility.array_to_string(task.p_comm), utility.array_to_string(task.p_pptr.p_comm)))

class AsepAuditFramework(MacAsep):

        def __init__(self):

                super().__init__("Audit Framework")

        def detect(self, task):

                if "audit" in utility.array_to_string(task.p_comm):
                        self.asep_evidences.add((self.asepName, True, task.p_pid, utility.array_to_string(task.p_comm), utility.array_to_string(task.p_pptr.p_comm)))

class AsepFolderActions(MacAsep):

        def __init__(self):

                super().__init__("Folder Actions")

        def detect (self, task):

              if "FolderActions" in utility.array_to_string(task.p_comm):
                        self.asep_evidences.add((self.asepName, True, task.p_pid, utility.array_to_string(task.p_comm), utility.array_to_string(task.p_pptr.p_comm)))

class AsepFynderSyncPlugins(MacAsep):

        def __init__(self):

                super().__init__("Fynder Sync Plugins")

        def detect(self, task):

                if "pkd" in utility.array_to_string(task.p_comm):
                        self.asep_evidences.add((self.asepName, True, task.p_pid, utility.array_to_string(task.p_comm), utility.array_to_string(task.p_pptr.p_comm)))

class AsepScriptFile(MacAsep):

        def __init__(self):

                super().__init__("Script File")

        def detect(self, task):

                if "osascript" in utility.array_to_string(task.p_comm):
                        self.asep_evidences.add((self.asepName, True, task.p_pid, utility.array_to_string(task.p_comm), utility.array_to_string(task.p_pptr.p_comm)))

class AsepDetectionByProcess(interfaces.plugins.PluginInterface):

        _required_framework_version = (2, 0, 0)

        @classmethod
        def get_requirements (self):
                return [
                        requirements.ModuleRequirement(name = 'kernel', description = 'macOS kernel', architectures = ["Intel32", "Intel64"])
                ]

        def generator (self):

                # Clase de los aseps
                aseps = [AsepCron(), AsepReopenedApps(), AsepKexts(), AsepDockTilePlugin(), AsepAuthPlugins(),
                         AsepLoginItems(), AsepSandboxedLoginApp(), AsepLoginHooks(), AsepProfiles(), AsepAudioPlugin(),
                         AsepSpotlight(), AsepQuicklook(), AsepScreenSaver(), AsepEmond(), AsepAuditFramework(), AsepFolderActions(),
                         AsepFynderSyncPlugins(), AsepScriptFile()]

                # Obtenemos los procesos
                tasks = pslist.PsList.list_tasks_allproc(self.context, self.config['kernel'])

                # Buscamos los procesos asociados con los ASEPs
                for task in tasks:

                        # Las tasks son punteros a memoria. Resolviendo la primera task resolvemos todas
                        if hasattr(task, 'dereference'):
                                task.dereference()

                        for asep in aseps:

                                asep.detect (task)

                # Devolvemos los ASEPs con su respectiva deteccion
                for asep in aseps:

                        # Devuelve una lista con las evidencias, la recorremos
                        for evidence in asep.get_evidences():
                                yield (0, evidence)

        def run (self):

                # Formato de las columnas que se imprimiran por pantalla
                return renderers.TreeGrid (
				[("ASEP Name", str), ("Found", bool), ("PID", int), ("Name", str), ("Parent Name", str)],
                                self.generator ()
		)
