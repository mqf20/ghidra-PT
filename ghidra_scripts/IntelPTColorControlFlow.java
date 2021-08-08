/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
//This colors the addresses in the control flow reconstructed by libipt's ptxed tool.
//
//@category Analysis.X86

import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;

import java.awt.Color;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.Scanner;

public class IntelPTColorControlFlow extends GhidraScript {

	public AddressSet readTraceFile() throws Exception {
		int numAddresses = 0;
		AddressSet addresses = new AddressSet();
		try {
			File myFile = askFile("Trace Log", "Choose file:");
			println(">> opening " + myFile);			
			Scanner myScanner = new Scanner(myFile);
			while (myScanner.hasNextLine()) {
				String line = myScanner.nextLine();
				if (line.isEmpty()) {
					continue;
				}
				if (line.startsWith("[")) {
					continue;
				}
				String[] tokens = line.split(" ");
				if (tokens.length < 2) {
					continue;
				}
				Address address = currentAddress.getAddress(tokens[0]);
				addresses.add(address);
				numAddresses++;
			}
			myScanner.close();
		} catch (FileNotFoundException e) {
			println(">> An error has occurred.");
			e.printStackTrace();
		}
		println(">> processed " + numAddresses + " addresses");
		return addresses;
	}

	@Override
	public void run() throws Exception {

		ColorizingService service = state.getTool().getService(ColorizingService.class);
		if (service == null) {
			println(">> Can't find ColorizingService service");
			return;
		}

		AddressSet addresses = readTraceFile();
		setBackgroundColor(addresses, Color.YELLOW);

	}

}
