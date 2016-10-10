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

import static org.junit.Assert.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class UtilityTest {
	
	private Map<String, String> map = new HashMap<>();
	
	@Before
	public void setUp() throws Exception {
		map.put("proxy.listener0", "1.8080.1.0..0.0.1.0..0..0..0.");
		map.put("proxy.listener1", "1.8080.210|4|164|185.0..0.0.1.0..0..0..0.");
		map.put("proxy.listener3", "1.8081.210|4|164|185.0..0.0.1.0..0..0..0.");
		map.put("proxy.listener4", "1.8079.210|4|164|185.0..0.0.1.0..0..0..0.");
		map.put("proxy.listener.bla", "blabla");
		map.put("key1", "xxxxxxxxxxxxxxxxxxxx");
		map.put("key2", "1.8079.210|4|164|185.0..0.0.1.0..0..0..0.");
	}

	@After
	public void tearDown() throws Exception {
	}

	@Test
	public void testComputePortNumber() {
		assertEquals(8082,Utility.computeUnusedPort(map));
	}

	@Test
	public void testgetEntriesHavingKeyStartingWith() {
		List<String> list = Utility.getEntriesHavingKeyStartingWith(map, Utility.PROXY_LISTENER_KEY);
		
		assertEquals(5, list.size());
		assertTrue(list.get(0).startsWith("1.808"));
	}
}
