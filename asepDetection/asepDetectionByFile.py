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

                        self.asep_evidences.add((self.asepName, False, "N/A"))

                return self.asep_evidences

        def isAsepDetected (self):

                return len(self.asep_evidences) > 0

class AsepCron (MacAsep):

        def __init__ (self):

                super().__init__ ("Cron")

        def detect (self, file):

                if re.search (r"/var/at/tabs/", file):
                        self.asep_evidences.add((self.asepName, True, file))

class AsepPeriodics(MacAsep):

        def __init__ (self):

                super().__init__ ("Periodics")

        def detect (self, file):

                if re.search (r"(System/Library/LaunchDaemons/com.apple.periodic-(daily|weekly|monthly)|/etc/periodic/(daily|weekly|monthly))", file):
                        self.asep_evidences.add((self.asepName, True, file))

class AsepAtJobs(MacAsep):

        def __init__ (self):

                super().__init__ ("At Jobs")

        def detect (self, file):

                if re.search (r"(System/Library/LaunchDaemons/com.apple.atrun.plist|/var/at/jobs/)", file):

                        self.asep_evidences.add((self.asepName, True, file))

class AsepReopenedApps(MacAsep):

        def __init__ (self):

                super().__init__ ("Reopened Apps")

        def detect (self, file):

               if re.search (r"com\.apple\.loginwindow\.[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\.plist", file):

                        self.asep_evidences.add((self.asepName, True, file))

class AsepKexts(MacAsep):

        def __init__ (self):

                super().__init__ ("Kexts")

        def detect (self, file):

              if re.search (r"/Library/Extensions/.*\.kext", file):

                        self.asep_evidences.add((self.asepName, True, re.sub(r"(\.kext).*", r"\1", file)))

class AsepDockTilePlugin(MacAsep):

        def __init__ (self):

                super().__init__ ("Dock Tile Plugin")

        def detect (self, file):

              if re.search (r"/Library/Preferences/com.apple.dock.plist", file):

                        self.asep_evidences.add((self.asepName, True, file))

class AsepExtensionsForMac(MacAsep):

        def __init__(self):

                super().__init__("Extensions For ")

        def detect (self, file):

              if re.search (r"/Library/Preferences/com.apple.preferences.extensions.ServicesWithUI.plist", file):

                        self.asep_evidences.add((self.asepName + "\"Actions\"", True, file))

              if re.search (r"/Library/Preferences/com.apple.preferences.extensions.PhotoEditing.plist", file):

                        self.asep_evidences.add((self.asepName + "\"Photos\"", True, file))

              if re.search (r"/Library/Preferences/com.apple.notificationcenterui.plist", file):

                        self.asep_evidences.add((self.asepName + "\"Today\"", True, file))

              if re.search (r"/Users/javi/Library/Preferences/com.apple.preferences.extensions.ShareMenu.plist", file):

                        self.asep_evidences.add((self.asepName + "\"Sharing Menu\"", True, file))

class AsepAuthPlugins(MacAsep):

        def __init__ (self):

                super().__init__ ("Auth Plugins")

        def detect (self, file):

              if re.search(r"/(Library/Security/SecurityAgentPlugins|System/Library/CoreServices/SecurityAgentPlugins)/.*\.bundle", file):

                        self.asep_evidences.add((self.asepName, True, re.sub(r"(\.bundle).*", r"\1", file)))

class AsepLoginItems(MacAsep):

        def __init__(self):

                super().__init__("Login Items")

        def detect(self, file):

              if re.search (r"/Library/Preferences/com.apple.loginitems.plist", file):

                        self.asep_evidences.add((self.asepName, True, file))

class AsepStartUpItems(MacAsep):

        def __init__ (self):

                super().__init__ ("StartUp Items")

        def detect (self, file):

              if re.search (r"/Library/StartupItem", file):

                        self.asep_evidences.add((self.asepName, True, file))

class AsepLoginHooks(MacAsep):

        def __init__ (self):

                super().__init__ ("Login Hooks")

        def detect (self, file):

              if re.search(r"Library/Preferences/com.apple.loginwindow.plist", file):

                        self.asep_evidences.add((self.asepName, True, file))

class AsepProfiles(MacAsep):

        def __init__ (self):

                super().__init__ ("Profiles")

        def detect (self, file):

              if re.search(r"/Library/PreferencePanes/Profiles.prefPane", file):

                        self.asep_evidences.add((self.asepName, True, re.sub(r"(\.prefPane).*", r"\1", file)))

class AsepLaunchDaemons(MacAsep):

        def __init__ (self):

                super().__init__ ("Launch Daemons")

        def detect (self, file):

              if re.search (r"Library/LaunchDaemons/", file):

                        self.asep_evidences.add((self.asepName, True, file))

class AsepLaunchAgents(MacAsep):

        def __init__ (self):

                super().__init__ ("Launch Agents")

        def detect (self, file):

              if re.search (r"Library/LaunchAgents/", file):

                        self.asep_evidences.add((self.asepName, True, file))

class AsepAudioPlugins(MacAsep):

        def __init__ (self):

                super().__init__ ("Audio Plugins")

        def detect (self, file):

              if re.search (r"Library/Audio/Plug-Ins/.*\.driver", file):

                        self.asep_evidences.add((self.asepName, True, re.sub(r"(\.driver).*", r"\1", file)))

              if re.search (r"System/Library/LaunchDaemons/com.apple.audio.coreaudiod.plist", file):

                        self.asep_evidences.add((self.asepName, True, file))

class AsepSpotlight(MacAsep):

        def __init__ (self):

                super().__init__ ("Spotlight")

        def detect (self, file):

              if re.search (r"Library/Spotlight/.*\.mdimporter", file):

                        self.asep_evidences.add((self.asepName, True, re.sub(r"(\.mdimporter).*", r"\1", file)))

              if re.search (r"System/Library/LaunchAgents/com.apple.spotlight", file):

                        self.asep_evidences.add((self.asepName, True, file))

class AsepQuickLook(MacAsep):

        def __init__ (self):

                super().__init__ ("QuickLook")

        def detect (self, file):

              if re.search (r"Library/QuickLook/.*\.qlgenerator", file):

                        self.asep_evidences.add((self.asepName, True, re.sub(r"(\.qlgenerator).*", r"\1", file)))

              if re.search (r"System/Library/LaunchAgents/com.apple.quicklook", file):

                        self.asep_evidences.add((self.asepName, True, file))

class AsepScreenSaver(MacAsep):

        def __init__ (self):

                super().__init__ ("Screen Saver")

        def detect (self, file):

              if re.search (r"Library/Screen Savers/.*\.saver", file):

                        self.asep_evidences.add((self.asepName, True,re.sub(r"(\.saver).*", r"\1", file)))

class AsepEmond(MacAsep):

        def __init__ (self):

                super().__init__ ("Emond")

        def detect (self, file):

              if re.search (r"(etc/emond.d/rules|System/Library/LaunchDaemons/com.apple.emond.plist)", file):

                        self.asep_evidences.add((self.asepName, True, file))

class AsepAuditFramework(MacAsep):

        def __init__ (self):

                super().__init__ ("Audit Framework")

        def detect (self, file):

              if re.search (r"(etc/security/audit_warn|System/Library/LaunchDaemons/com.apple.auditd.plist)", file):

                        self.asep_evidences.add((self.asepName, True, file))

class AsepFolderActions(MacAsep):

        def __init__ (self):

                super().__init__ ("Folder Actions")

        def detect (self, file):

              if re.search (r"(Library/Scripts/Folder|System/Library/LaunchAgents/com.apple.FolderActionsDispatcher.plist)", file):

                        self.asep_evidences.add((self.asepName, True, file))

class AsepTerminalConfig(MacAsep):

        def __init__ (self):

                super().__init__ ("Terminal Config")

        def detect (self, file):

              if re.search (r"Library/Preferences/com.apple.Terminal.plist", file):

                        self.asep_evidences.add((self.asepName, True, file))

class AsepShellStartupFiles(MacAsep):

        def __init__ (self):

                super().__init__ ("Shell Startup Files")

        def detect (self, file):

              if re.search (r"/.zshrc|/.zlogin|/.zshenv.zwc|/.zshenv|/.zprofile|/etc/zshenv|/etc/zprofile|/etc/zshrc|/etc/zlogin|/.zlogout|/etc/zlogout|/.bashrc|/.profile|/etc/profile", file):

                        self.asep_evidences.add((self.asepName, True, file))

class AsepColorPicker(MacAsep):

        def __init__ (self):

                super().__init__ ("Color Picker")

        def detect (self, file):

              if re.search (r"Library/ColorPickers", file):

                        self.asep_evidences.add((self.asepName, True, file))

class AsepPAM(MacAsep):

        def __init__ (self):

                super().__init__ ("PAM Module")

        def detect (self, file):

              if re.search (r"etc/pam.d/", file):

                        self.asep_evidences.add((self.asepName, True, file))

class AsepPreferencePane(MacAsep):

        def __init__ (self):

                super().__init__ ("Pref Pane")

        def detect (self, file):

              if re.search (r"PreferencePanes/.*\.prefPane", file):

                        self.asep_evidences.add((self.asepName, True, re.sub(r"(\.prefPane).*", r"\1", file)))

class AsepFynderSyncPlugins(MacAsep):

        def __init__ (self):

                super().__init__ ("Fynder Sync Plugins")

        def detect (self, file):

              if re.search (r".*\.appex", file):

                        self.asep_evidences.add((self.asepName, True, re.sub(r"(\.appex).*", r"\1", file)))

class AsepDetectionByFile(interfaces.plugins.PluginInterface):

        _required_framework_version = (2, 0, 0)

        @classmethod
        def get_requirements (self):
                return [
                        requirements.ModuleRequirement(name = 'kernel', description = 'macOS kernel', architectures = ["Intel32", "Intel64"])
                ]

        def generator (self):

                # Clase de los aseps
                aseps = [AsepCron(), AsepPeriodics(), AsepAtJobs(),
                         AsepReopenedApps(), AsepKexts(), AsepDockTilePlugin(), AsepAuthPlugins(), AsepLoginItems(),
                         AsepStartUpItems(), AsepLoginHooks(), AsepProfiles(),
                         AsepLaunchDaemons(), AsepLaunchAgents(), AsepAudioPlugins(),
                         AsepSpotlight(), AsepQuickLook(), AsepScreenSaver(), AsepEmond(), AsepAuditFramework(),
                         AsepFolderActions(), AsepTerminalConfig(), AsepShellStartupFiles(), AsepColorPicker(), AsepPAM(),
                         AsepPreferencePane(), AsepFynderSyncPlugins()]

                # Obtenemos los descriptores de ficheros abiertos (hay más, pero no tenemos acceso porque están en disco y no en la RAM)
                files = list_files.List_Files.list_files(self.context, self.config['kernel'])

                # Buscamos los procesos asociados con los ASEPs
                for file in files:

                        for asep in aseps:

                                # File es un vector, en la segunda posicion se encuentra el nombre del fichero
                                asep.detect (file[1])

                # Devolvemos los ASEPs con su respectiva deteccion
                for asep in aseps:

                        # Devuelve una lista con las evidencias, la recorremos
                        for evidence in asep.get_evidences():
                                yield (0, evidence)

        def run (self):

                # Formato de las columnas que se imprimiran por pantalla
                return renderers.TreeGrid (
                                [("ASEP Name", str), ("Found", bool), ("File associated", str)],
                                self.generator ()
                )
