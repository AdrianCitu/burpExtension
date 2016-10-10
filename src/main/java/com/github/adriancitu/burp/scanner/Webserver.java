/**
 * MIT License
 *
 * Copyright (c) 2016 Adrian CITU
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

package com.github.adriancitu.burp.scanner;

import java.io.IOException;
import java.net.InetSocketAddress;

import burp.IBurpExtenderCallbacks;

import com.github.adriancitu.burp.scanner.report.ScannerReportHandler;
import com.sun.net.httpserver.HttpServer;

public class Webserver {

    /**
     * system property representing the port on which the server will listen.
     */
	private static final String SCANNER_REPORT_PORT_PROPERTY = "scanner.report.port";
    /**
     * system property representing the url on which the report will be served.
     */
	private static final String SCANNER_REPORT_URL_PROPERTY = "scanner.report.url";
    /**
     * the default url if no system property specified.
     */
	private static final String SCANNER_REPORT_DEFAULT_URL = "/scanner/report";
	private final HttpServer server;

	public Webserver(final IBurpExtenderCallbacks callback) throws IOException {
		final int port = computePort(callback);
		final String url = System.getProperty(
				SCANNER_REPORT_URL_PROPERTY, 
				SCANNER_REPORT_DEFAULT_URL);

		
		server = HttpServer.create(new InetSocketAddress(port), 0);
		server.createContext(url, new ScannerReportHandler(callback));
		server.setExecutor(null); // creates a default executor
		server.start();
		
		Utility.writeToConsole(
				callback, 
				"Webserver started on port [" 
				+ port + "] under url [" + url +"]",
				false);
	}

    /**
     * Compute the port on which the web server will run.
     * First check if any port has been specified as command line
     * parameter and use it, otherwise the server will start on
     * MAX(ports of listeners) + 1.
     *
     * @param callback
     * @return
     */
	private int computePort(final IBurpExtenderCallbacks callback) {
		int port;
		final String portAsString = System.getProperty(SCANNER_REPORT_PORT_PROPERTY);
		
		if (portAsString == null) {
			port = Utility.computeUnusedPort(
					callback.saveConfig());
			
			Utility.writeToConsole(callback, 
					"No system property named [" 
							+ SCANNER_REPORT_PORT_PROPERTY 
							+ "] found in the command line;" 
							+ " will compute a port automatically...",
							false);
		} else {
			try {
				port = Integer.valueOf(portAsString);	
			} catch (final NumberFormatException e) {
				
				Utility.writeToConsole(callback, "System property [" 
						+ SCANNER_REPORT_URL_PROPERTY 
						+"] cannod be parsed as an Integer; the value is [" 
						+ portAsString+ "]", true);
				port = Utility.computeUnusedPort(
						callback.saveConfig());
			}
			
		}
		return port;
	}
}
