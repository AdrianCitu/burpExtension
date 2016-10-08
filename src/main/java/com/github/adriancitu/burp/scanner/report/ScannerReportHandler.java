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

package com.github.adriancitu.burp.scanner.report;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.util.List;

import burp.IBurpExtenderCallbacks;
import burp.IParameter;
import burp.IRequestInfo;

import com.github.adriancitu.burp.scanner.Utility;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

public class ScannerReportHandler implements HttpHandler {

	private static final String OUTPUT_DEFAULT_PARAMETER = "output";
	private static final String HTML = "HTML";
	private final IBurpExtenderCallbacks callback;

	public ScannerReportHandler(final IBurpExtenderCallbacks cll) {
		callback = cll;
	}

	@Override
	public void handle(final HttpExchange t) throws IOException {
		
		final String outputType = computeTheOutputParameter(t);
		
		final File tempFile = File.createTempFile(
				"scanReport" + System.currentTimeMillis(), 
				".tmp");
		tempFile.deleteOnExit();
		
		callback.generateScanReport(outputType, 
				callback.getScanIssues(null), 
				tempFile);
		
		final String response = new String(Files.readAllBytes(tempFile.toPath()));
		t.sendResponseHeaders(200, response.length());
		final OutputStream os = t.getResponseBody();
		os.write(response.getBytes());
		os.close();
		
		Utility.writeToConsole(
				callback, 
				"Scanner report was requested;" 
				+ " The served file was written on the parh :" 
				+ tempFile.getAbsolutePath(), false);
		
	}

	private String computeTheOutputParameter(final HttpExchange t) {
		final IRequestInfo analyzeRequest = callback.getHelpers()
				.analyzeRequest(t.getRequestURI().toString().getBytes());
		final List<IParameter> parameters = analyzeRequest.getParameters();
		String output = HTML;
		for (final IParameter iParameter : parameters) {
			if (OUTPUT_DEFAULT_PARAMETER.equalsIgnoreCase(iParameter.getName())) {
				output = iParameter.getValue();
				break;
			}
		}
		return output;
	}
}
