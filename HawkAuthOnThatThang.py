import hmac
import hashlib
import base64
import time
from urlparse import urlparse  # For parsing URLs
import random
import string
from burp import IBurpExtender, ITab, IHttpListener  # Burp-specific imports
from javax.swing import JPanel, JLabel, JTextField, JCheckBox, JButton, BorderFactory, JOptionPane, JComboBox, BoxLayout, Box  # For the UI
from java.awt import BorderLayout, Dimension, GridBagLayout, GridBagConstraints, Insets, Component

class BurpExtender(IBurpExtender, ITab, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.callbacks.setExtensionName("Hawk Authenticator")

        # Default values for settings
        self.hawk_id = ""
        self.hawk_key = ""
        self.hawk_algorithm = "sha256"
        self.hawk_user = ""
        self.hawk_nonce = ""
        self.hawk_ext = ""
        self.hawk_app = ""
        self.hawk_dlg = ""
        self.include_payload_hash = False
        self.hawk_enabled = False

        # Create the main settings panel
        self.mainPanel = JPanel(BorderLayout())
        self.create_settings_ui()

        # Add the extension tab to Burp
        callbacks.addSuiteTab(self)

        # Register HTTP listener to modify requests
        callbacks.registerHttpListener(self)

    def create_settings_ui(self):
        # Main panel with BoxLayout for top-left alignment
        self.mainPanel = JPanel()
        self.mainPanel.setLayout(BoxLayout(self.mainPanel, BoxLayout.Y_AXIS))
        self.mainPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))  # Padding around the whole panel

        # Helper method to create small text boxes
        def create_small_text_field(columns):
            text_field = JTextField(columns)
            text_field.setMaximumSize(Dimension(150, 24))  # Set max size to avoid expanding
            return text_field

        # Helper method to add components with GridBagLayout and top-left align them
        def add_component(panel, component, x, y, gridwidth=1):
            constraints = GridBagConstraints()
            constraints.gridx = x
            constraints.gridy = y
            constraints.gridwidth = gridwidth
            constraints.anchor = GridBagConstraints.FIRST_LINE_START  # Align components to top-left
            constraints.insets = Insets(5, 5, 5, 5)  # Padding around the components
            constraints.fill = GridBagConstraints.NONE  # Prevent components from expanding
            panel.add(component, constraints)

        # Main settings panel (small size)
        settingsPanel = JPanel(GridBagLayout())
        settingsPanel.setBorder(BorderFactory.createTitledBorder("Hawk Authentication Settings"))
        settingsPanel.setAlignmentX(Component.LEFT_ALIGNMENT)
        settingsPanel.setMaximumSize(Dimension(400, 200))  # Set the panel to a fixed smaller size

        add_component(settingsPanel, JLabel("Hawk Auth ID:"), 0, 0)
        self.hawk_id_field = create_small_text_field(20)
        add_component(settingsPanel, self.hawk_id_field, 1, 0)

        add_component(settingsPanel, JLabel("Hawk Auth Key:"), 0, 1)
        self.hawk_key_field = create_small_text_field(20)
        add_component(settingsPanel, self.hawk_key_field, 1, 1)

        add_component(settingsPanel, JLabel("Algorithm:"), 0, 2)
        self.hawk_algorithm_field = JComboBox(["sha256", "sha1"])  # Dropdown for selecting algorithm
        self.hawk_algorithm_field.setMaximumSize(Dimension(150, 24))  # Set max size to avoid expanding
        add_component(settingsPanel, self.hawk_algorithm_field, 1, 2)

        # Advanced settings panel (small size)
        advancedPanel = JPanel(GridBagLayout())
        advancedPanel.setBorder(BorderFactory.createTitledBorder("Advanced Settings"))
        advancedPanel.setAlignmentX(Component.LEFT_ALIGNMENT)
        advancedPanel.setMaximumSize(Dimension(400, 300))  # Set the panel to a fixed smaller size

        add_component(advancedPanel, JLabel("User:"), 0, 0)
        self.hawk_user_field = create_small_text_field(20)
        add_component(advancedPanel, self.hawk_user_field, 1, 0)

        add_component(advancedPanel, JLabel("App:"), 0, 1)
        self.hawk_app_field = create_small_text_field(20)
        add_component(advancedPanel, self.hawk_app_field, 1, 1)

        add_component(advancedPanel, JLabel("Dlg:"), 0, 2)
        self.hawk_dlg_field = create_small_text_field(20)
        add_component(advancedPanel, self.hawk_dlg_field, 1, 2)

        add_component(advancedPanel, JLabel("Nonce:"), 0, 3)
        self.hawk_nonce_field = create_small_text_field(20)
        add_component(advancedPanel, self.hawk_nonce_field, 1, 3)

        add_component(advancedPanel, JLabel("Ext:"), 0, 4)
        self.hawk_ext_field = create_small_text_field(20)
        add_component(advancedPanel, self.hawk_ext_field, 1, 4)

        add_component(advancedPanel, JLabel("Timestamp (optional):"), 0, 5)
        self.hawk_timestamp_field = create_small_text_field(20)
        add_component(advancedPanel, self.hawk_timestamp_field, 1, 5)

        self.include_payload_checkbox = JCheckBox("Include Payload Hash")
        add_component(advancedPanel, self.include_payload_checkbox, 0, 6, gridwidth=2)

        # Save and toggle buttons
        save_button = JButton("Save", actionPerformed=self.save_settings)
        add_component(settingsPanel, save_button, 0, 3)

        self.toggle_button = JButton("Enable Hawk Auth", actionPerformed=self.toggle_hawk_auth)
        add_component(settingsPanel, self.toggle_button, 1, 3)

        # Align settings and advanced panels within a BoxLayout
        containerPanel = JPanel()
        containerPanel.setLayout(BoxLayout(containerPanel, BoxLayout.Y_AXIS))
        containerPanel.setAlignmentX(Component.LEFT_ALIGNMENT)  # Ensure everything is left-aligned

        containerPanel.add(settingsPanel)
        containerPanel.add(Box.createRigidArea(Dimension(0, 10)))  # Add small space between panels
        containerPanel.add(advancedPanel)

        # Set containerPanel to the minimum size needed to fit its content
        containerPanel.setMaximumSize(containerPanel.getPreferredSize())
        containerPanel.setAlignmentX(Component.LEFT_ALIGNMENT)

        # Add the containerPanel to mainPanel
        self.mainPanel.add(containerPanel)

    def save_settings(self, event):
        self.hawk_id = self.hawk_id_field.getText()
        self.hawk_key = self.hawk_key_field.getText()
        self.hawk_algorithm = self.hawk_algorithm_field.getSelectedItem()  # Dropdown selection
        self.hawk_user = self.hawk_user_field.getText()
        self.hawk_app = self.hawk_app_field.getText()
        self.hawk_dlg = self.hawk_dlg_field.getText()
        self.hawk_nonce = self.hawk_nonce_field.getText()
        self.hawk_ext = self.hawk_ext_field.getText()
        self.hawk_timestamp = self.hawk_timestamp_field.getText()  # Optional timestamp
        self.include_payload_hash = self.include_payload_checkbox.isSelected()

        JOptionPane.showMessageDialog(None, "Settings saved successfully!")

    def toggle_hawk_auth(self, event):
        if self.hawk_enabled:
            self.hawk_enabled = False
            self.toggle_button.setText("Enable Hawk Auth")
            JOptionPane.showMessageDialog(None, "Hawk Authentication Disabled")
        else:
            self.hawk_enabled = True
            self.toggle_button.setText("Disable Hawk Auth")
            JOptionPane.showMessageDialog(None, "Hawk Authentication Enabled")

    def getTabCaption(self):
        return "Hawk Auth"

    def getUiComponent(self):
        return self.mainPanel

    # Process the HTTP requests for Proxy, Repeater, etc.
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest or not self.hawk_enabled:
            return

        # Extract request details
        request_info = self.helpers.analyzeRequest(messageInfo)
        headers = list(request_info.getHeaders())
        body = messageInfo.getRequest()[request_info.getBodyOffset():]

        # Build Hawk credentials dictionary
        credentials = {
            'id': self.hawk_id,
            'key': self.hawk_key,
            'algorithm': self.hawk_algorithm
        }

        # Generate Hawk Authentication Header
        hawk_header = self.generate_hawk_header(
            credentials=credentials,
            method=request_info.getMethod(),
            url=request_info.getUrl().toString(),
            content=body
        )

        # Add Hawk authorization header
        headers.append('Authorization: {}'.format(hawk_header))
        messageInfo.setRequest(self.helpers.buildHttpMessage(headers, body))

    def generate_hawk_header(self, credentials, method, url, content=""):
        # Generate nonce and timestamp if not provided
        timestamp = self.hawk_timestamp if self.hawk_timestamp else str(int(time.time()))
        nonce = self.hawk_nonce if self.hawk_nonce else self.generate_nonce()

        # Parse the URL to extract host and port
        parsed_url = urlparse(url)
        host = parsed_url.hostname
        port = parsed_url.port if parsed_url.port else (443 if parsed_url.scheme == 'https' else 80)
        path = parsed_url.path
        if parsed_url.query:
            path += '?' + parsed_url.query

        # Calculate payload hash if needed
        payload_hash = ''
        if content and self.include_payload_hash:
            payload_hash = self.calculate_payload_hash(content)

        # Build normalized string for the MAC calculation
        normalized_string = self.build_normalized_string(
            timestamp, nonce, method, path, host, port, payload_hash
        )

        # Generate MAC
        mac = self.calculate_mac(credentials['key'], normalized_string, credentials['algorithm'])

        # Build Hawk Authorization header
        hawk_header = 'Hawk id="{id}", ts="{ts}", nonce="{nonce}", mac="{mac}"'.format(
            id=credentials['id'],
            ts=timestamp,
            nonce=nonce,
            mac=mac
        )

        if payload_hash:
            hawk_header += ', hash="{hash}"'.format(hash=payload_hash)

        if self.hawk_ext:
            hawk_header += ', ext="{}"'.format(self.hawk_ext)

        if self.hawk_app:
            hawk_header += ', app="{}"'.format(self.hawk_app)

        if self.hawk_dlg:
            hawk_header += ', dlg="{}"'.format(self.hawk_dlg)

        # Log the Hawk header for debugging
        print("Burp Hawk Header: " + hawk_header)
        return hawk_header

    def build_normalized_string(self, timestamp, nonce, method, path, host, port, payload_hash):
        # Build the normalized string according to the Hawk specification
        normalized = []
        normalized.append("hawk.1.header")
        normalized.append(timestamp)
        normalized.append(nonce)
        normalized.append(method.upper())
        normalized.append(path)
        normalized.append(host)
        normalized.append(str(port))
        normalized.append(payload_hash)  # Empty if no payload
        normalized.append(self.hawk_ext)  # Any additional Hawk extension data
        normalized.append('')  # Add a trailing newline
        return '\n'.join(normalized)

    def calculate_payload_hash(self, content):
        # Calculate the payload hash (used for POST or content in general)
        sha256 = hashlib.sha256()
        sha256.update("hawk.1.payload\n".encode('utf-8'))
        sha256.update("text/plain\n".encode('utf-8'))  # Assuming plain text content
        sha256.update(content)
        sha256.update('\n'.encode('utf-8'))
        return base64.b64encode(sha256.digest())

    def calculate_mac(self, key, normalized_string, algorithm):
        # Generate the HMAC with the given algorithm and key
        hmac_gen = hmac.new(key.encode('ascii'), normalized_string.encode('utf-8'), hashlib.sha256)
        return base64.b64encode(hmac_gen.digest())

    def generate_nonce(self):
        # Generate a simple random string for the nonce
        return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(6))