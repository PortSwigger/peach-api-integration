
package PeachApi;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IScanIssue;
import burp.customGUI.ScannerResults;
import com.peachapisecurity.api.Fault;
import com.peachapisecurity.api.FaultData;
import com.peachapisecurity.api.Job;
import com.peachapisecurity.api.PeachApiSecurity;
import java.io.PrintWriter;
import java.net.URL;
import java.time.LocalDateTime;
import java.util.ArrayList;
import javax.swing.SwingWorker;
import static org.apache.commons.lang.StringEscapeUtils.escapeHtml;

public class StatusUpdateWorker extends SwingWorker<Void, Void>
{
    PeachApiPreferences _prefs;
    ScannerResults _status;
    PeachApiSecurity _apiSec;
    IBurpExtenderCallbacks _callbacks;
    private ArrayList<Integer> _seenFaultIds = new ArrayList<Integer>();

    public StatusUpdateWorker(PeachApiSecurity apiSec, ScannerResults status, PeachApiPreferences prefs, IBurpExtenderCallbacks callbacks)
    {
        super();

        _apiSec = apiSec;
        _status = status;
        _prefs = prefs;
        _callbacks = callbacks;
        
        _prefs.setStatusUpdateWorker(this);
    }

    @Override
    public Void doInBackground()
    {
        try
        {
            boolean _isCancelled = false;

            Job[] jobs = _apiSec.getJobs();
            Job job = jobs[0];
            String jobId = job.id;
            int faultCount = 0;

            while(true)
            {
                try
                {
                    _isCancelled = isCancelled();

                    job = _apiSec.getJob(jobId);

                    if(job.reason != null && job.reason.length() > 0)
                    {
                        _status.labelStatus.setText(job.state + " (" + job.reason + ")");
                    }
                    else
                    {
                        _status.labelStatus.setText(job.state);
                    }

                    _status.labelStarted.setText(job.createdAt);

                    if(job.finishedAt != null)
                    {
                        _status.labelFinished.setText(job.finishedAt);
                    }

                    _status.testStatusBar.setMaximum(job.totalTestCount);
                    _status.testStatusBar.setValue(job.executedTestCount);

                    _status.labelTestCount.setText(
                            job.executedTestCount + " of " + job.totalTestCount);

                    if(!job.state.equals("Running") || _isCancelled)
                    {
                        // shutdown worker
                        return null;
                    }

                    Fault[] faults = _apiSec.getJobFaults(jobId);
                    ScanIssue issue = null;
                    IHttpService service = null;

                    _status.labelIssues.setText(Integer.toString(faults.length));

                    if(faults.length <= faultCount)
                        continue;

                    for(int cnt = 0; cnt < faults.length; cnt++)
                    {
                        if(_seenFaultIds.contains(faults[cnt].id))
                            continue;

                        Fault fault = _apiSec.getJobFault(jobId, faults[cnt].id);
                        if(fault == null)
                        {
                            throw new NullPointerException("Fault "+faults[cnt].id+" was not found.");
                        }

                        if(fault.visibility != null && !fault.visibility.equals("Normal"))
                        {
                            continue;
                        }
                        
                        // Currently the API does not return known vulnerabliities correctly
                        // for now we will skip them
                        if(fault.assertion.equalsIgnoreCase("Known Vulnerabilities"))
                        {
                            continue;
                        }

                        String urlStr = getFaultUrl(fault);

                        IHttpRequestResponse[] msgs = _callbacks.getSiteMap(urlStr);
                        if(msgs.length > 0)
                        {
                            service = msgs[0].getHttpService();
                        }

                        FaultData faultData = fault.faultData;
                        msgs = new IHttpRequestResponse[3];
                        msgs[0] = new HttpReqResp("Actual (Modified) Request/Response", faultData.actualRequest, faultData.actualResponse, service);
                        msgs[1] = new HttpReqResp("Origional (Unmodified) Request", faultData.originalRequest, new byte[0], service);
                        msgs[2] = new HttpReqResp("Recorded Request/Response", faultData.recordedRequest, faultData.recordedResponse, service);

                        String detection = fault.detection;
                        if(detection != null)
                            detection = escapeHtml(detection)
                                    .replaceAll("\\\\(.)", "$1")
                                    .replaceAll("\n", "<br/>");

                        String description = fault.description;
                        if(description != null)
                            description = escapeHtml(description)
                                    .replaceAll("\\\\(.)", "$1")
                                    .replaceAll("\n", "<br/>");

                        issue = new ScanIssue(
                            new URL(urlStr),    // url
                            fault.title,        // issueName
                            0x08000000,         // issue type
                            getBurpSeverity(fault),// severity
                            getBurpConfidence(fault),// confidence
                            detection,          // issue background
                            null,               // remediation background
                            description,        // issue details
                            null,               // remediation detail
                            msgs,               // [] httpMessages
                            service             // httpService
                        );

                        try
                        {
                            _callbacks.addScanIssue(issue);
                        }
                        catch(Exception issueEx)
                        {
                            throw issueEx;
                        }

                        faultCount = cnt+1;
                        _seenFaultIds.add(fault.id);
                    }
                }
                catch(Exception ex)
                {
                    throw ex;
                }

                if(_isCancelled)
                {
                    break;
                }

                try
                {
                    Thread.sleep(3000);
                }
                catch(Exception ex)
                {
                    break; // interupted exception
                }
            }
        }
        catch(Exception exx)
        {
            PrintWriter stderr = new PrintWriter(_callbacks.getStderr());
            stderr.print("vvv ");
            stderr.print(LocalDateTime.now().toString());
            stderr.println(" vvvvvvvvvvvvvvvvvvvvvvvvvv");
            stderr.println("Error while updating test status page.");
            stderr.println("Please check the Peach API Security -> Settings tab in burp.");
            stderr.println("If error continues, please report to support@peach.tech.");
            stderr.println("Include full output from this screen and also the generated support bundle from the Peach API Security web UI.");
            stderr.println("");
            stderr.println("    Extension Version: " + _prefs.getVersion());
            stderr.println("Peach API Version: " + PeachApiSecurity.getApiVersion());
            stderr.println("");
            stderr.println("Exception information:");
            stderr.println(exx.toString());
            stderr.println("^^^^^^^^^^^^^^^^^^^^^^^^^^^");
            stderr.flush();
        }
        finally
        {
            // re-enable the testing button
            _prefs.getExtension().testContextMenu.enable();
        }

        return null;
    }

    private String getFaultUrl(Fault fault)
    {
        String[] opSplit = fault.testCase.split(" ");
        return opSplit[1];
    }

    private String getBurpSeverity(Fault fault)
    {
        switch(fault.impact)
        {
            case "Severe":
                return "High";
            case "Moderate":
                return "Medium";
            case "Minor":
                return "Low";
        }

        return "Information";
    }

    private String getBurpConfidence(Fault fault)
    {
        return "Firm";
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

    class HttpReqResp implements IHttpRequestResponse
    {
        private String _comment;
        private byte[] _request;
        private byte[] _response;
        private IHttpService _httpService;

        public HttpReqResp(String comment, byte[] request, byte[] response, IHttpService service)
        {
            _comment = comment;
            _request = request;
            _response = response;
            _httpService = service;
        }

        @Override
        public byte[] getRequest() {
            return _request;
        }

        @Override
        public void setRequest(byte[] message) {
        }

        @Override
        public byte[] getResponse() {
            return _response;
        }

        @Override
        public void setResponse(byte[] message) {
        }

        @Override
        public String getComment() {
            return _comment;
        }

        @Override
        public void setComment(String comment) {
        }

        @Override
        public String getHighlight() {
            return null;
        }

        @Override
        public void setHighlight(String color) {
        }

        @Override
        public IHttpService getHttpService() {
            return _httpService;
        }

        @Override
        public void setHttpService(IHttpService httpService) {
        }
    }

    class ScanIssue implements IScanIssue
    {
        URL _url;
        String _issueName;
        int _issueType;
        String _severity;
        String _confidence;
        String _issueBackground;
        String _remediationBackground;
        String _issueDetail;
        String _remediationDetail;
        IHttpRequestResponse[] _httpMessages;
        IHttpService _httpService;

        ScanIssue(
            URL url,
            String issueName,
            int issueType,
            String severity,
            String confidence,
            String issueBackground,
            String remediationBackground,
            String issueDetail,
            String remediationDetail,
            IHttpRequestResponse[] httpMessages,
            IHttpService httpService)
        {

            _url = url;
            _issueName = issueName;
            _issueType = issueType;
            _severity = severity;
            _confidence = confidence;
            _issueBackground = issueBackground;
            _remediationBackground = remediationBackground;
            _issueDetail = issueDetail;
            _remediationDetail = remediationDetail;
            _httpMessages = httpMessages;
            _httpService = httpService;
        }

        @Override
        public URL getUrl()
        {
            return _url;
        }

        @Override
        public String getIssueName() {
            return _issueName;
        }

        @Override
        public int getIssueType() {
            return _issueType;
        }

        @Override
        public String getSeverity() {
            return _severity;
        }

        @Override
        public String getConfidence() {
            return _confidence;
        }

        @Override
        public String getIssueBackground() {
            return _issueBackground;
        }

        @Override
        public String getRemediationBackground() {
            return _remediationBackground;
        }

        @Override
        public String getIssueDetail() {
            return _issueDetail;
        }

        @Override
        public String getRemediationDetail() {
            return _remediationDetail;
        }

        @Override
        public IHttpRequestResponse[] getHttpMessages() {
            return _httpMessages;
        }

        @Override
        public IHttpService getHttpService() {
            return _httpService;
        }
    }
}
