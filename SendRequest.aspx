<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="SendRequest.aspx.cs" Inherits="ServicePrividerAMA.SendRequest" %>

<!DOCTYPE html>

<html xmlns="http://www.w3.org/1999/xhtml">
<head runat="server">
    <title></title>
</head>
<body onload="document.forms[0].submit()">
     <form id="form1" runat="server" action="" method="post" enableviewstate="false">
    <div>
        <asp:HiddenField ID="RelayState" runat="server" />
        <asp:HiddenField ID="SAMLRequest" runat="server" />
    </div>
    <noscript>
        <div>
            <input type="submit" value="Continue" />
        </div>
    </noscript>
    </form>
</body>
</html>
