/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package PeachApi;

import burp.IContextMenuInvocation;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import com.peachapisecurity.api.PeachApiSecurity;
import com.peachapisecurity.api.PeachState;
import java.io.PrintWriter;
import java.time.LocalDateTime;
import javax.swing.JOptionPane;
import javax.swing.SwingWorker;

public class JobWorker extends SwingWorker<Void, Void>
{
    private final burp.IBurpExtenderCallbacks _callbacks;
    private final PeachApiPreferences _prefs;
    private final IContextMenuInvocation _invocation;
    private final burp.IExtensionHelpers _helpers;
    
    public JobWorker(burp.IBurpExtenderCallbacks callbacks, 
            IContextMenuInvocation invocation, PeachApiPreferences prefs)
    {
        super();
        
        _callbacks = callbacks;
        _prefs = prefs;
        _invocation = invocation;
        _helpers = _callbacks.getHelpers();
        
        _prefs.setJobWorker(this);
    }

    @Override
    protected Void doInBackground() throws Exception
    {
        try
        {
            PeachState state = PeachState.Continue;
            IHttpRequestResponse root = _invocation.getSelectedMessages()[0];
            String rootUrl = _helpers.analyzeRequest(root).getUrl().toString();

            IHttpRequestResponse[] msgs = _callbacks.getSiteMap(rootUrl);

            PeachApiSecurity apiSec = new PeachApiSecurity(
                _prefs.getApiUrl(), 
                "Token " + _prefs.getApiToken(), 
                "", 
                _prefs.getApiUrl());

            try
            {
                apiSec.sessionSetup(_prefs.getProject(), _prefs.getProfile());
            }
            catch(Exception e)
            {
                String msg = 
                    "An error occured starting the test.\n\n"+
                    "Please check the Peach API Security -> Settings tab in burp.\n"+
                    "If error continues, please report to support@peach.tech.\n\n"+
                    "Error: "+e.getMessage();

                JOptionPane.showMessageDialog(_prefs.getBurpFrame(), 
                    msg,
                    "Error", JOptionPane.ERROR_MESSAGE);
                
                // enable context menu or it will stay disabled
                _prefs.getExtension().testContextMenu.enable();

                throw e;
            }
            
            // Create scan restusts page
            
            _prefs.getApiTab().showTestStatus(this, apiSec);
            
            //

            for (IHttpRequestResponse msg : msgs)
            {
                if(isCancelled())
                {
                    break;
                }
                
                IRequestInfo reqInfo = _helpers.analyzeRequest(msg);
                String msgUrl = reqInfo.getUrl().toString();
                
                while(!isCancelled())
                {
                    apiSec.testSetup();
                    apiSec.testCase(reqInfo.getMethod() + " " + msgUrl);

                    _callbacks.makeHttpRequest(
                        apiSec.getProxyHost(), 
                        apiSec.getProxyPort(),
                        false,
                        msg.getRequest());
                    
                    state = apiSec.testTeardown();
                    if(state != PeachState.Continue)
                    {
                        break;
                    }
                }
                
                if(state == PeachState.Error)
                {
                    break;
                }
            }
            
            apiSec.suiteTeardown();
            apiSec.sessionTeardown();
        }
        catch(Exception ex)
        {
            PrintWriter stderr = new PrintWriter(_callbacks.getStderr());
            stderr.print("vvv ");
            stderr.print(LocalDateTime.now().toString());
            stderr.println(" vvvvvvvvvvvvvvvvvvvvvvvvvv");
            stderr.println("Error while running testing job.");
            stderr.println("Please check the Peach API Security -> Settings tab in burp.");
            stderr.println("If error continues, please report to support@peach.tech.");
            stderr.println("Include full output from this screen and also the generated support bundle from the Peach API Security web UI.");
            stderr.println("");
            stderr.println("    Extension Version: " + _prefs.getVersion());
            stderr.println("Peach API Version: " + PeachApiSecurity.getApiVersion());
            stderr.println("");
            stderr.println("Exception information:");
            stderr.println(ex.toString());
            stderr.println("^^^^^^^^^^^^^^^^^^^^^^^^^^^");
            stderr.flush();
        }

        return null;
    }

    @Override
    public void done()
    {
        try
        {
             get();
        }
        catch (Exception ignore) {}
    }
}
