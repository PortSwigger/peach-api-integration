package burp;

import PeachApi.JobWorker;
import PeachApi.PeachApiPreferences;
import PeachApi.StatusUpdateWorker;
import PeachApi.TestWithPeachApiMenu;
import com.peachapisecurity.api.PeachApiSecurity;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JMenuItem;

public class BurpExtender implements IBurpExtender, IContextMenuFactory, IExtensionStateListener
{
    public burp.IBurpExtenderCallbacks _callbacks;
    private PeachApiPreferences _prefs;
    private burp.IExtensionHelpers _helpers;
    public TestWithPeachApiMenu testContextMenu;
    
    @Override
    public void registerExtenderCallbacks (IBurpExtenderCallbacks callbacks)
    {
        _prefs = new PeachApiPreferences();
        _callbacks = callbacks;
        _helpers = callbacks.getHelpers();
        
        _prefs.setExtension(this);
        
        // set our extension name
        callbacks.setExtensionName("Peach API Security Extension");
        
        callbacks.registerContextMenuFactory(this);
        callbacks.registerExtensionStateListener(this);
        
        // Preferences tab
        callbacks.addSuiteTab(new burp.customGUI.PeachApiTab(_prefs, callbacks));
        
        // Output a loaded successfuly message
        PrintStream sout = new PrintStream(_callbacks.getStdout());
        
        sout.println("");
        sout.println("Peach API Security Burp Extension");
        sout.println("Copyright (c) Peach Tech");
        sout.println("");
        sout.println("Extension Version: " + _prefs.getVersion());
        sout.println("Peach API Version: " + PeachApiSecurity.getApiVersion());
        sout.println("");
        sout.println("Extention loaded successfully!");
        sout.println("");
    }
    
    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation)
    {
        if(invocation.getInvocationContext() != 
           IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TREE)
        {
            return null;
        }
        
        List<JMenuItem> menuItems = new ArrayList<JMenuItem>();
        
        testContextMenu = new TestWithPeachApiMenu(_callbacks, invocation, _prefs);
        menuItems.add(new JMenuItem(testContextMenu));
        
        return menuItems;
    }

    @Override
    public void extensionUnloaded()
    {
        PrintStream sout = new PrintStream(_callbacks.getStdout());
        sout.println("");
        sout.println("Unloading extension...");
        
        JobWorker jobWorker = _prefs.getJobWorker();
        StatusUpdateWorker statusWorker = _prefs.getStatusUpdateWorker();
        
        if(jobWorker != null)
        {
            if(!jobWorker.isDone())
            {
                jobWorker.cancel(false);
            }

            sout.println("  * Waiting for workers to exit");
            while(true)
            {
                if(jobWorker.isDone() && (statusWorker == null || statusWorker.isDone()))
                    break;
            }
        }
        
        sout.println("  * Done");
        sout.println("");
        sout.println("Extension unloaded!");
        sout.println("");
    }
}

// end
