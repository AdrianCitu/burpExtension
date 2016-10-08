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

import java.io.PrintWriter;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import burp.IBurpExtenderCallbacks;

public final class Utility {

	private static final String LINE_SEPARATOR = "line.separator";
	static final String PROXY_LISTENER_KEY = "proxy.listener";

	private Utility() {
	}

	public static List<String> getEntriesHavingKeyStartingWith(
			final Map<String, String> map, final String prefix) {
		return map.entrySet().stream()
				.filter(p -> p.getKey().startsWith(prefix))
				.map(p -> p.getValue()).collect(Collectors.toList());
	}

	public static int computePortNumberFromProxySettings(final Map<String, String> settings) {

		return getEntriesHavingKeyStartingWith(settings, PROXY_LISTENER_KEY)
				.stream()
				    //create a list of integers representing the ports
					.map(p -> {
							try {
								return new Integer(p.split("\\.")[1]);	
							} catch (final Exception e) {
								System.out.println(p);
								return -1;
							}
							
						})
						.collect(Collectors.toList())
							.stream()
							    //find the max frm the port list
								.max(Comparator.naturalOrder()).get()
									//add 1 to the max port
									+ 1;

	}
	
	public static void writeToConsole(final IBurpExtenderCallbacks callback, 
			final String message, 
			final boolean toError) {
		final PrintWriter stdout = new PrintWriter(
				toError ? callback.getStderr() : callback.getStdout(), true);
		stdout.append(message).append(System.getProperty(LINE_SEPARATOR));
		stdout.close();
	}
}
