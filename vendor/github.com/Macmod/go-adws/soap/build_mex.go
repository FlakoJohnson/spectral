package soap

import "fmt"

// BuildMexGetRequest builds a WS-MetadataExchange GetMetadata request.
// It uses a WS-Transfer Get directed at the MEX endpoint. The To header contains
// ResourceInstance as a placeholder which callers normalize to the actual endpoint
// URL (e.g. via NormalizeSOAPAddressing in the wsenum package).
func BuildMexGetRequest() string {
	msgID := generateMessageID()
	return fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://www.w3.org/2005/08/addressing">
	<s:Header>
		<wsa:Action s:mustUnderstand="1">%s</wsa:Action>
		<wsa:MessageID>%s</wsa:MessageID>
		<wsa:ReplyTo>
			<wsa:Address>%s</wsa:Address>
		</wsa:ReplyTo>
		<wsa:To s:mustUnderstand="1">%s</wsa:To>
	</s:Header>
	<s:Body/>
</s:Envelope>`, ActionGet, msgID, AddressAnonymous, ResourceInstance)
}
