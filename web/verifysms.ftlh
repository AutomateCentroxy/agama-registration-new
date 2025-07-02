[#ftl output_format="HTML"]
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Verify SMS OTP</title></head>
<body>

  
    
    
  
  
    <h2>Step 2: Verify SMS OTP</h2>

    [#if errorMessage??]
      <p id="error" style="color: red;">${errorMessage}</p>
    [/#if]

    [#if infoMessage??]
      <p id="info" style="color: green;">${infoMessage}</p>
    [/#if]

    <form method="post">
      <label for="otpCode">Enter the OTP sent to your phone:</label><br>
      <input type="text" id="otpCode" name="code" required=""><br><br>

      <!-- Hidden field to track resend -->
      <input type="hidden" id="hasRequestedNewCode" name="hasRequestedNewCode" value="no">

      <button type="submit" onclick="document.getElementById('hasRequestedNewCode').value='no'">Verify</button>
      <button type="submit" onclick="document.getElementById('hasRequestedNewCode').value='yes'">Resend OTP</button>
    </form>
  
</body>


</html>