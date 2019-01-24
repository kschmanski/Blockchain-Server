	osascript <<EOF
	tell app "Terminal"
		do script "cd Desktop/'CSC 435'/Blockchain/src/assignment && java --add-modules java.xml.bind Blockchain 0 && java Blockchain 0"
	end tell

	tell app "Terminal"
		do script "cd Desktop/'CSC 435'/Blockchain/src/assignment && java --add-modules java.xml.bind Blockchain 1 && java Blockchain 1"
	end tell

	tell app "Terminal"
		do script "cd Desktop/'CSC 435'/Blockchain/src/assignment && java --add-modules java.xml.bind Blockchain 2 && java Blockchain 2"
	end tell

	EOF