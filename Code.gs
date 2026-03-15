/**
 * mgcryan - SERVER LOGIC (SPEED OPTIMIZED + UNIVERSAL PASSKEY + ELITE DB ACCESS + FORCE RESETS + DEEP TELEMETRY LOGGING)
 */

function sha256(str) {
  if (!str) return "";
  const signature = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, str);
  return signature.map(byte => (byte < 0 ? byte + 256 : byte).toString(16).padStart(2, '0')).join('');
}

function setupSheet(ss, name, headers) {
  let sheet = ss.getSheetByName(name);
  if (!sheet) {
    sheet = ss.insertSheet(name);
    sheet.appendRow(headers);
    sheet.getRange(1, 1, 1, headers.length).setFontWeight("bold").setBackground("#d9d9d9");
  }
  return sheet;
}

function ensureUserColumns(sheet) {
  if (sheet.getLastRow() === 0) {
    sheet.appendRow(["ID", "Username", "Password", "Role", "Name", "Auth", "Status", "BiometricID", "BioStatus", "DB_Access", "ForceReset"]);
    return;
  }
  const headers = sheet.getRange(1, 1, 1, sheet.getLastColumn()).getValues()[0];
  if (String(headers[0]).trim().toUpperCase() !== "ID") sheet.insertColumnBefore(1);
  if (sheet.getLastColumn() < 8 || headers[7] !== "BiometricID") { sheet.getRange(1, 8).setValue("BiometricID"); }
  if (sheet.getLastColumn() < 9 || headers[8] !== "BioStatus") { sheet.getRange(1, 9).setValue("BioStatus"); }
  if (sheet.getLastColumn() < 10 || headers[9] !== "DB_Access") { sheet.getRange(1, 10).setValue("DB_Access"); }
  if (sheet.getLastColumn() < 11 || headers[10] !== "ForceReset") { sheet.getRange(1, 11).setValue("ForceReset"); }
}

function getNextId(sheet, prefix) {
  const data = sheet.getDataRange().getValues();
  let max = 0;
  for (let i = 1; i < data.length; i++) {
    const idVal = String(data[i][0]).trim();
    if (idVal.startsWith(prefix + "-")) {
      const num = parseInt(idVal.split("-")[1], 10);
      if (!isNaN(num) && num > max) max = num;
    }
  }
  return prefix + "-" + String(max + 1).padStart(4, "0");
}

function getSetting(sheet, key) {
  if (sheet.getLastRow() === 0) return "false";
  const data = sheet.getDataRange().getValues();
  for (let r of data) { 
    if (String(r[0]).trim() === key) return String(r[1]).trim(); 
  }
  return "false";
}

function updateSetting(sheet, key, value) {
  if (sheet.getLastRow() === 0) {
    sheet.appendRow(["Key", "Value"]);
    sheet.getRange(1, 1, 1, 2).setFontWeight("bold").setBackground("#d9d9d9");
  }
  const data = sheet.getDataRange().getValues();
  for (let i = 0; i < data.length; i++) {
    if (String(data[i][0]).trim() === key) {
      sheet.getRange(i + 1, 2).setValue(value);
      return;
    }
  }
  sheet.appendRow([key, value]);
}

function doPost(e) {
  try {
    const data = JSON.parse(e.postData.contents);
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    
    const userSheet = ss.getSheetByName("Users");
    ensureUserColumns(userSheet);
    
    const logSheet = setupSheet(ss, "Logs", ["Date", "Time", "Operator_ID", "Operator_Username", "Operator_Name", "Target", "Action", "IP_Address", "OS", "Architecture", "Device_Type", "Model", "Browser", "CPU"]);
    
    // Hot-patch: Upgrades existing Log sheets to 14 columns instantly without data loss
    if (logSheet.getLastRow() > 0) {
      const logHeaders = logSheet.getRange(1, 1, 1, logSheet.getLastColumn()).getValues()[0];
      if (logHeaders[3] !== "Operator_Username") {
          logSheet.insertColumnBefore(4);
          logSheet.getRange(1, 4).setValue("Operator_Username");
      }
      if (logSheet.getLastColumn() < 14) {
           logSheet.getRange(1, 8, 1, 7).setValues([["IP_Address", "OS", "Architecture", "Device_Type", "Model", "Browser", "CPU"]]);
           logSheet.getRange(1, 1, 1, 14).setFontWeight("bold").setBackground("#d9d9d9");
      }
    }

    const sessionSheet = setupSheet(ss, "Sessions", ["ID", "Username", "Role", "Date", "Time", "Token"]);
    const settingsSheet = setupSheet(ss, "Settings", ["Key", "Value"]);
    const pageSheet = setupSheet(ss, "Pages", ["Page_ID", "Title", "URL", "Allowed_Users", "Status"]);
    const secSheet = setupSheet(ss, "Security", ["Encrypted_Security_Keys"]);
    const appSheet = setupSheet(ss, "Approvals", ["Req_ID", "Username", "Type", "NewHash", "Status", "Date"]);
    
    const d = new Date();
    const dateStr = "'" + Utilities.formatDate(d, "GMT+5:30", "yyyy-MM-dd");
    const timeStr = "'" + Utilities.formatDate(d, "GMT+5:30", "HH:mm:ss");

    if (data.action === "setup_system") {
      if (userSheet.getLastRow() > 1) return ContentService.createTextOutput("403");
      const newId = data.devId ? data.devId.trim() : "MGC-0001";
      userSheet.appendRow([newId, data.username, sha256(data.password), "Developer", data.name, sha256(data.auth), "Offline", "", "Enabled", "Users,Pages,Security,Settings,Approvals", ""]);
      if(secSheet.getLastRow() === 0) secSheet.appendRow(["Encrypted_Security_Keys"]);
      secSheet.appendRow([sha256(data.securityKey)]);
      logSheet.appendRow([dateStr, timeStr, newId, data.username, data.name, "System", "Initialized Root Developer Account"]);
      return ContentService.createTextOutput("200");
    }

    if (data.action === "log_action") {
      logSheet.appendRow([dateStr, timeStr, data.operatorId, data.operatorUsername || "-", data.operatorName, data.target, data.details]);
      return ContentService.createTextOutput("200");
    }

    if (data.action === "request_reset") {
      const reqId = "REQ-" + Utilities.getUuid().substring(0,6).toUpperCase();
      appSheet.appendRow([reqId, data.username, data.type, sha256(data.newPassword), "Pending", dateStr + " " + timeStr]);
      logSheet.appendRow([dateStr, timeStr, "SYSTEM", "SYSTEM", "System Auto", "User - " + data.username, `Requested ${data.type} Reset/Setup`]);
      return ContentService.createTextOutput("200");
    }

    if (data.action === "resolve_reset") {
      const appRows = appSheet.getDataRange().getValues();
      for (let j = 1; j < appRows.length; j++) {
        if (String(appRows[j][0]) === String(data.reqId)) {
          if (data.decision === "Approve") {
            const rows = userSheet.getDataRange().getValues();
            for (let i = 1; i < rows.length; i++) {
              if (String(rows[i][1]).trim() === String(appRows[j][1]).trim()) {
                if (appRows[j][2] === "Password") {
                  userSheet.getRange(i + 1, 3).setValue(appRows[j][3]);
                } else if (appRows[j][2] === "AuthCode") {
                  userSheet.getRange(i + 1, 6).setValue(appRows[j][3]);
                }
                break;
              }
            }
          }
          appSheet.deleteRow(j + 1);
          logSheet.appendRow([dateStr, timeStr, data.operatorId, data.operatorUsername || "-", data.operatorName, appRows[j][1], `${data.decision}d ${appRows[j][2]} request`]);
          return ContentService.createTextOutput("200");
        }
      }
      return ContentService.createTextOutput("404");
    }

    if (data.action === "set_force_reset") {
      const rows = userSheet.getDataRange().getValues();
      for (let i = 1; i < rows.length; i++) {
        if (String(rows[i][1]).trim() === String(data.targetUser).trim()) {
           let current = String(rows[i][10] || "").trim();
           let currentArr = current ? current.split(',').map(x => x.trim()).filter(x => x) : [];
           if (!currentArr.includes(data.resetType)) {
               currentArr.push(data.resetType);
               userSheet.getRange(i + 1, 11).setValue(currentArr.join(','));
           }
           logSheet.appendRow([dateStr, timeStr, data.operatorId, data.operatorUsername || "-", data.operatorName, data.targetUser, `Mandated ${data.resetType} change`]);
           return ContentService.createTextOutput("200");
        }
      }
      return ContentService.createTextOutput("404");
    }

    if (data.action === "execute_force_reset") {
      const rows = userSheet.getDataRange().getValues();
      for (let i = 1; i < rows.length; i++) {
        if (String(rows[i][1]).trim() === String(data.username).trim()) {
           if (data.type === "Password") {
               userSheet.getRange(i + 1, 3).setValue(sha256(data.newHash));
           } else if (data.type === "AuthCode") {
               userSheet.getRange(i + 1, 6).setValue(sha256(data.newHash));
           }
           
           let current = String(rows[i][10] || "").trim();
           current = current.split(',').map(x => x.trim()).filter(x => x && x !== data.type).join(',');
           
           userSheet.getRange(i + 1, 11).setValue(current);
           logSheet.appendRow([dateStr, timeStr, "SYSTEM", "SYSTEM", "System Auto", data.username, `Completed mandatory ${data.type} update`]);
           return ContentService.createTextOutput("200");
        }
      }
      return ContentService.createTextOutput("404");
    }

    if (data.action === "update_inline_access") {
      const rows = userSheet.getDataRange().getValues();
      for (let i = 1; i < rows.length; i++) {
        if (String(rows[i][1]).trim() === String(data.targetUser).trim()) {
          userSheet.getRange(i + 1, 10).setValue(data.dbAccess);
          logSheet.appendRow([dateStr, timeStr, data.operatorId, data.operatorUsername || "-", data.operatorName, data.targetUser, `${data.operatorName} modified granular access`]);
          return ContentService.createTextOutput("200");
        }
      }
      return ContentService.createTextOutput("404");
    }

    if (data.action === "toggle_bio") {
      const rows = userSheet.getDataRange().getValues();
      for (let i = 1; i < rows.length; i++) {
        if (String(rows[i][1]).trim() === String(data.targetUser).trim()) {
          const currentStatus = String(rows[i][8]).trim() === "Disabled" ? "Enabled" : "Disabled";
          userSheet.getRange(i + 1, 9).setValue(currentStatus);
          logSheet.appendRow([dateStr, timeStr, data.operatorId, data.operatorUsername || "-", data.operatorName, data.targetUser, `${data.operatorName} set Passkey login to ${currentStatus}`]);
          return ContentService.createTextOutput("200");
        }
      }
      return ContentService.createTextOutput("404");
    }

    if (data.action === "toggle_passkey") {
      updateSetting(settingsSheet, "PASSKEY_LOGIN", data.state);
      logSheet.appendRow([dateStr, timeStr, data.operatorId, data.operatorUsername || "-", data.operatorName, "System", data.state ? "Enabled Global Passkey Login" : "Disabled Global Passkey Login"]);
      return ContentService.createTextOutput("200");
    }

    if (data.action === "register_bio") {
      const rows = userSheet.getDataRange().getValues();
      for (let i = 1; i < rows.length; i++) {
        if (String(rows[i][1]).trim() === String(data.username).trim()) {
          userSheet.getRange(i + 1, 8).setValue(data.bioId);
          userSheet.getRange(i + 1, 9).setValue("Enabled"); 
          logSheet.appendRow([dateStr, timeStr, rows[i][0], data.username, rows[i][4], "Security", "Registered Passkey"]);
          return ContentService.createTextOutput("200");
        }
      }
      return ContentService.createTextOutput("404");
    }

    if (data.action === "verify_auth_bio") {
      const rows = userSheet.getDataRange().getValues();
      for (let i = 1; i < rows.length; i++) {
        if (String(rows[i][1]).trim() === String(data.username).trim()) {
          
          const forceReset = String(rows[i][10] || "").trim();
          if (forceReset.includes("AuthCode")) {
             return ContentService.createTextOutput("FORCE_AUTH");
          }

          if (String(rows[i][7]).trim() === String(data.bioId).trim() && String(rows[i][8]).trim() !== "Disabled") {
            const devInfo = data.deviceInfo || {};
            const ip = devInfo.ip || "-";
            const os = devInfo.os || "-";
            const arch = devInfo.architecture || "-";
            const devType = devInfo.device || "-";
            const model = devInfo.model || "-";
            const browser = devInfo.browser || "-";
            const cpu = devInfo.cpu || "-";

            logSheet.appendRow([dateStr, timeStr, rows[i][0], rows[i][1], rows[i][4], "Database", "Logged into Database Management via Passkey", ip, os, arch, devType, model, browser, cpu]);
            return ContentService.createTextOutput("200");
          } else {
            logSheet.appendRow([dateStr, timeStr, rows[i][0], rows[i][1], rows[i][4], "Database", "Failed Database Auth Attempt (Passkey)"]);
            return ContentService.createTextOutput("403");
          }
        }
      }
      return ContentService.createTextOutput("404");
    }

    if (data.action === "login_bio") {
      const rows = userSheet.getDataRange().getValues();
      const isMaint = getSetting(settingsSheet, "MAINTENANCE") === "true";
      const passkeyLogin = getSetting(settingsSheet, "PASSKEY_LOGIN") !== "false";
      for (let i = 1; i < rows.length; i++) {
        const storedBio = String(rows[i][7]).trim();
        if (storedBio !== "" && storedBio === data.bioId) {
          
          const matchedUsername = String(rows[i][1]).trim();
          const role = String(rows[i][3]).trim();
          const userId = String(rows[i][0]).trim();
          
          const forceReset = String(rows[i][10] || "").trim();
          if (forceReset.includes("Password")) {
             return ContentService.createTextOutput(JSON.stringify({ status: "FORCE_PASS", username: matchedUsername }));
          }

          if (!passkeyLogin && !role.toLowerCase().includes("developer")) return ContentService.createTextOutput("403_PASSKEY_LOGIN");

          const bioStatus = String(rows[i][8]).trim();
          if (bioStatus === "Disabled") return ContentService.createTextOutput("403_BIO");
          
          if (isMaint && !role.toLowerCase().includes("developer")) return ContentService.createTextOutput("503");
          
          const sessionToken = Utilities.getUuid();
          userSheet.getRange(i + 1, 7).setValue("Online");
          sessionSheet.appendRow([userId, matchedUsername, role, dateStr, timeStr, sessionToken]);
          
          const devInfo = data.deviceInfo || {};
          const ip = devInfo.ip || "-";
          const os = devInfo.os || "-";
          const arch = devInfo.architecture || "-";
          const devType = devInfo.device || "-";
          const model = devInfo.model || "-";
          const browser = devInfo.browser || "-";
          const cpu = devInfo.cpu || "-";
          
          logSheet.appendRow([dateStr, timeStr, userId, matchedUsername, rows[i][4], "Web App", "Logged into Web App via Passkey", ip, os, arch, devType, model, browser, cpu]);
          
          let allowedPages = [];
          if (pageSheet.getLastRow() > 1) {
            const pages = pageSheet.getDataRange().getValues().slice(1);
            pages.forEach(p => {
              const access = String(p[3]).toUpperCase();
              const pStatus = String(p[4] || "Visible").trim();
              if (pStatus !== "Hidden" && (access === "ALL" || access.includes(userId))) allowedPages.push({ title: p[1], url: p[2] });
            });
          }

          return ContentService.createTextOutput(JSON.stringify({
            status: "200", token: sessionToken,
            user: { id: userId, username: matchedUsername, role: rows[i][3], name: rows[i][4], dbAccess: rows[i][9] || '', hasBio: true, bioStatus: bioStatus },
            links: allowedPages,
            bioEnabled: true
          }));
        }
      }
      return ContentService.createTextOutput("401_PASS");
    }

    if (data.action === "login") {
      const rows = userSheet.getDataRange().getValues();
      const isMaint = getSetting(settingsSheet, "MAINTENANCE") === "true";
      const hashedAttempt = sha256(data.password);
      
      let userFound = false;
      for (let i = 1; i < rows.length; i++) {
        if (String(rows[i][1]).trim() === String(data.username).trim()) {
          userFound = true;
          if (String(rows[i][2]).trim() === hashedAttempt) {
            
            const matchedUsername = String(rows[i][1]).trim();
            const role = String(rows[i][3]).trim();
            const userId = String(rows[i][0]).trim();
            
            const forceReset = String(rows[i][10] || "").trim();
            if (forceReset.includes("Password")) {
               return ContentService.createTextOutput(JSON.stringify({ status: "FORCE_PASS", username: matchedUsername }));
            }

            const hasBio = String(rows[i][7]).trim() !== "";
            const bioStatus = String(rows[i][8]).trim() || "Enabled";
            
            if (isMaint && !role.toLowerCase().includes("developer")) return ContentService.createTextOutput("503");
            
            const sessionToken = Utilities.getUuid();
            userSheet.getRange(i + 1, 7).setValue("Online");
            sessionSheet.appendRow([userId, matchedUsername, role, dateStr, timeStr, sessionToken]);
            
            const devInfo = data.deviceInfo || {};
            const ip = devInfo.ip || "-";
            const os = devInfo.os || "-";
            const arch = devInfo.architecture || "-";
            const devType = devInfo.device || "-";
            const model = devInfo.model || "-";
            const browser = devInfo.browser || "-";
            const cpu = devInfo.cpu || "-";
            
            logSheet.appendRow([dateStr, timeStr, userId, matchedUsername, rows[i][4], "Web App", "Logged into Web App", ip, os, arch, devType, model, browser, cpu]);
            
            let allowedPages = [];
            if (pageSheet.getLastRow() > 1) {
              const pages = pageSheet.getDataRange().getValues().slice(1);
              pages.forEach(p => {
                const access = String(p[3]).toUpperCase();
                const pStatus = String(p[4] || "Visible").trim(); 
                if (pStatus !== "Hidden" && (access === "ALL" || access.includes(userId))) allowedPages.push({ title: p[1], url: p[2] });
              });
            }

            return ContentService.createTextOutput(JSON.stringify({
              status: "200", token: sessionToken,
              user: { id: userId, username: matchedUsername, role: rows[i][3], name: rows[i][4], dbAccess: rows[i][9] || '', hasBio: hasBio, bioStatus: bioStatus },
              links: allowedPages,
              bioEnabled: hasBio,
              bioStatus: bioStatus
            }));
          }
        }
      }
      return ContentService.createTextOutput(userFound ? "401_PASS" : "404_USER");
    }

    if (data.action === "verify_auth") {
      const rows = userSheet.getDataRange().getValues();
      const hashedAuthAttempt = sha256(data.authCode);
      for (let i = 1; i < rows.length; i++) {
        if (String(rows[i][1]).trim() === String(data.username).trim()) {
          
          const forceReset = String(rows[i][10] || "").trim();
          if (forceReset.includes("AuthCode")) {
             return ContentService.createTextOutput("FORCE_AUTH");
          }

          const storedAuth = String(rows[i][5]).trim();
          if (storedAuth === "") {
             return ContentService.createTextOutput("403_SETUP_REQUIRED");
          }
          
          if (storedAuth === hashedAuthAttempt) {
            const devInfo = data.deviceInfo || {};
            const ip = devInfo.ip || "-";
            const os = devInfo.os || "-";
            const arch = devInfo.architecture || "-";
            const devType = devInfo.device || "-";
            const model = devInfo.model || "-";
            const browser = devInfo.browser || "-";
            const cpu = devInfo.cpu || "-";

            logSheet.appendRow([dateStr, timeStr, rows[i][0], rows[i][1], rows[i][4], "Database", "Logged into Database Management", ip, os, arch, devType, model, browser, cpu]);
            return ContentService.createTextOutput("200");
          } else {
            logSheet.appendRow([dateStr, timeStr, rows[i][0], rows[i][1], rows[i][4], "Database", "Failed Database Auth Attempt"]);
            return ContentService.createTextOutput("403");
          }
        }
      }
      return ContentService.createTextOutput("404");
    }

    if (data.action === "toggle_maintenance") {
      updateSetting(settingsSheet, "MAINTENANCE", data.state);
      if (data.state === true && sessionSheet.getLastRow() > 1) {
        const sessions = sessionSheet.getDataRange().getValues();
        for(let s = sessions.length - 1; s >= 1; s--) {
          if(!String(sessions[s][2]).toLowerCase().includes("developer")) {
            sessionSheet.deleteRow(s + 1);
          }
        }
      }
      logSheet.appendRow([dateStr, timeStr, data.operatorId, data.operatorUsername || "-", data.operatorName, "System", data.state ? "Turned Maintenance Mode ON" : "Turned Maintenance Mode OFF"]);
      return ContentService.createTextOutput("200");
    }

    if (data.action === "logout" || data.action === "force_logout") {
      const target = data.targetUser || data.username;
      
      if (sessionSheet.getLastRow() > 1) {
        const sessions = sessionSheet.getDataRange().getValues();
        for(let i = sessions.length - 1; i >= 1; i--) {
          if (data.action === "logout" && String(sessions[i][5]).trim() === String(data.token).trim()) {
            sessionSheet.deleteRow(i + 1);
            logSheet.appendRow([dateStr, timeStr, data.operatorId, data.operatorUsername || "-", data.operatorName, "Self", "Logged out of Web App (Device specific)"]);
            break;
          } else if (data.action === "force_logout" && String(sessions[i][1]).trim() === String(target).trim()) {
            sessionSheet.deleteRow(i + 1);
          }
        }
      }

      if (data.action === "force_logout") {
        logSheet.appendRow([dateStr, timeStr, data.operatorId, data.operatorUsername || "-", data.operatorName, target, `${data.operatorName} forcefully logged out user ${target}`]);
      }

      let stillOnline = false;
      if (sessionSheet.getLastRow() > 1) {
         const remSessions = sessionSheet.getDataRange().getValues();
         for(let i = 1; i < remSessions.length; i++) {
            if(String(remSessions[i][1]).trim() === String(target).trim()) { stillOnline = true; break; }
         }
      }

      const uRows = userSheet.getDataRange().getValues();
      for(let i = 1; i < uRows.length; i++) {
        if(String(uRows[i][1]).trim() === String(target).trim()) {
           userSheet.getRange(i + 1, 7).setValue(stillOnline ? "Online" : "Offline");
           break;
        }
      }
      return ContentService.createTextOutput("200");
    }

    if (data.action === "bulk_logout") {
      const targets = data.targets;
      if (sessionSheet.getLastRow() > 1) {
        const sessions = sessionSheet.getDataRange().getValues();
        for(let s = sessions.length - 1; s >= 1; s--) {
          if(targets.includes(String(sessions[s][1]).trim())) { sessionSheet.deleteRow(s + 1); }
        }
      }
      const uRows = userSheet.getDataRange().getValues();
      for(let t of targets) {
        for(let i = 1; i < uRows.length; i++) {
          if(String(uRows[i][1]).trim() === String(t).trim()) { userSheet.getRange(i + 1, 7).setValue("Offline"); break; }
        }
      }
      logSheet.appendRow([dateStr, timeStr, data.operatorId, data.operatorUsername || "-", data.operatorName, "Multiple Users", `${data.operatorName} mass logged out ${targets.length} users`]);
      return ContentService.createTextOutput("200");
    }

    if (data.action === "bulk_delete" || data.action === "delete") {
      const hashedCode = sha256(data.securityKey);
      const codes = secSheet.getRange(1, 1, Math.max(1, secSheet.getLastRow())).getValues().flat().map(String);
      
      if (codes.includes(hashedCode)) {
        const targets = data.action === "delete" ? [data.targetUser] : data.targets;
        let deleted = 0;

        for (let t of targets) {
          const rows = userSheet.getDataRange().getValues();
          for (let i = rows.length - 1; i >= 1; i--) {
            if (String(rows[i][1]).trim() === String(t).trim()) {
              userSheet.deleteRow(i + 1);
              deleted++;
              break;
            }
          }
        }
        
        if (sessionSheet.getLastRow() > 1) {
          const sessions = sessionSheet.getDataRange().getValues();
          for (let s = sessions.length - 1; s >= 1; s--) {
            if (targets.includes(String(sessions[s][1]).trim())) { sessionSheet.deleteRow(s + 1); }
          }
        }
        
        if(data.action === "delete") {
          logSheet.appendRow([dateStr, timeStr, data.operatorId, data.operatorUsername || "-", data.operatorName, data.targetUser, `${data.operatorName} permanently deleted user ${data.targetUser}`]);
        } else {
          logSheet.appendRow([dateStr, timeStr, data.operatorId, data.operatorUsername || "-", data.operatorName, "Multiple Users", `${data.operatorName} deleted ${deleted} users`]);
        }
        return ContentService.createTextOutput("200");
      }
      logSheet.appendRow([dateStr, timeStr, data.operatorId, data.operatorUsername || "-", data.operatorName, "System", "Failed Delete (Invalid Security Key)"]);
      return ContentService.createTextOutput("403");
    }

    if (data.action === "add" || data.action === "update") {
      const rows = userSheet.getDataRange().getValues();
      const isUpdate = data.action === "update";
      
      if (!isUpdate || String(data.targetUser).trim() !== String(data.username).trim()) {
        for (let j = 1; j < rows.length; j++) {
          if (String(rows[j][1]).trim() === String(data.username).trim()) return ContentService.createTextOutput("409");
        }
      }

      if (isUpdate) {
        for (let i = 1; i < rows.length; i++) {
          if (String(rows[i][1]).trim() === String(data.targetUser).trim()) {
            let finalPass = data.password ? sha256(data.password) : rows[i][2]; 
            let finalAuth = data.auth ? sha256(data.auth) : rows[i][5];
            userSheet.getRange(i + 1, 2, 1, 5).setValues([[data.username, finalPass, data.role, data.name, finalAuth]]);
            if (data.dbAccess !== undefined) {
               userSheet.getRange(i + 1, 10).setValue(data.dbAccess);
            }
            
            logSheet.appendRow([dateStr, timeStr, data.operatorId, data.operatorUsername || "-", data.operatorName, data.username, `${data.operatorName} updated user details for ${data.username}`]);
            return ContentService.createTextOutput("200");
          }
        }
      } else {
        let newId = "";
        if (data.customId && data.customId !== "") {
            const idExists = rows.some(r => String(r[0]).trim().toUpperCase() === String(data.customId).trim().toUpperCase());
            if (idExists) return ContentService.createTextOutput("409_ID");
            newId = data.customId.trim();
        } else {
            newId = getNextId(userSheet, "MGC");
        }

        userSheet.appendRow([newId, data.username, sha256(data.password), data.role, data.name, sha256(data.auth), "Offline", "", "Enabled", data.dbAccess || "", ""]);
        logSheet.appendRow([dateStr, timeStr, data.operatorId, data.operatorUsername || "-", data.operatorName, data.username, `${data.operatorName} added new user ${data.username} (${newId})`]);
        return ContentService.createTextOutput("200");
      }
    }

    if (data.action === "add_key") {
      if (!String(data.operatorRole).toLowerCase().includes("developer")) return ContentService.createTextOutput("403");
      secSheet.appendRow([sha256(data.newKey)]);
      logSheet.appendRow([dateStr, timeStr, data.operatorId, data.operatorUsername || "-", data.operatorName, "Security", "Created a new Master Security Key"]);
      return ContentService.createTextOutput("200");
    }
    
    if (data.action === "revoke_key") {
      if (!String(data.operatorRole).toLowerCase().includes("developer")) return ContentService.createTextOutput("403");
      const rowIndex = parseInt(data.rowIndex, 10);
      if(rowIndex && rowIndex <= secSheet.getLastRow()) {
        secSheet.deleteRow(rowIndex);
        logSheet.appendRow([dateStr, timeStr, data.operatorId, data.operatorUsername || "-", data.operatorName, "Security", "Revoked a Master Security Key"]);
        return ContentService.createTextOutput("200");
      }
    }

    if (data.action === "save_page") {
      const isUpdate = data.pageId !== "NEW";
      const pStatus = data.status || "Visible";
      if (isUpdate) {
        const rows = pageSheet.getDataRange().getValues();
        for (let i = 1; i < rows.length; i++) {
          if (String(rows[i][0]).trim() === String(data.pageId).trim()) {
            pageSheet.getRange(i + 1, 2, 1, 4).setValues([[data.title, data.url, data.allowed, pStatus]]);
            logSheet.appendRow([dateStr, timeStr, data.operatorId, data.operatorUsername || "-", data.operatorName, data.title, `Updated Page configuration (${pStatus})`]);
            return ContentService.createTextOutput("200");
          }
        }
      } else {
        const newId = getNextId(pageSheet, "PG");
        pageSheet.appendRow([newId, data.title, data.url, data.allowed, pStatus]);
        logSheet.appendRow([dateStr, timeStr, data.operatorId, data.operatorUsername || "-", data.operatorName, data.title, `Added New Page Route`]);
        return ContentService.createTextOutput("200");
      }
    }
    
    if (data.action === "delete_page") {
      const rows = pageSheet.getDataRange().getValues();
      for (let i = 1; i < rows.length; i++) {
        if (String(rows[i][0]).trim() === String(data.pageId).trim()) {
          pageSheet.deleteRow(i + 1);
          logSheet.appendRow([dateStr, timeStr, data.operatorId, data.operatorUsername || "-", data.operatorName, "Page", "Deleted Page Route"]);
          return ContentService.createTextOutput("200");
        }
      }
    }

  } catch (err) {
    return ContentService.createTextOutput("ERROR: " + err.message);
  }
}

function doGet(e) {
  try {
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    const settingsSheet = ss.getSheetByName("Settings");
    const maint = settingsSheet ? getSetting(settingsSheet, "MAINTENANCE") === "true" : false;
    const passkeyLogin = settingsSheet ? getSetting(settingsSheet, "PASSKEY_LOGIN") !== "false" : true;
    const userSheet = ss.getSheetByName("Users");
    
    if (e.parameter && e.parameter.mode === "status") {
      let devs = [];
      let isSetup = true;
      if(userSheet && userSheet.getLastRow() > 1) {
        isSetup = false;
        const uData = userSheet.getDataRange().getValues().slice(1);
        devs = uData.filter(r => String(r[3]).toLowerCase().includes('developer')).map(r => String(r[1]).toLowerCase());
      }
      return ContentService.createTextOutput(JSON.stringify({ maintenance: maint, passkeyLogin: passkeyLogin, devs: devs, isSetup: isSetup })).setMimeType(ContentService.MimeType.JSON);
    }

    if (!userSheet) return ContentService.createTextOutput("ERROR: 'Users' sheet missing.");
    const logSheet = ss.getSheetByName("Logs");
    const sessionSheet = ss.getSheetByName("Sessions");
    const pageSheet = ss.getSheetByName("Pages");
    const secSheet = ss.getSheetByName("Security");
    const appSheet = setupSheet(ss, "Approvals", ["Req_ID", "Username", "Type", "NewHash", "Status", "Date"]);
    
    let activeUsernames = [];
    let validTokens = [];
    if (sessionSheet && sessionSheet.getLastRow() > 1) {
      const sessionData = sessionSheet.getRange(2, 1, sessionSheet.getLastRow() - 1, 6).getValues();
      sessionData.forEach(r => {
        const uname = String(r[1]).trim();
        const token = String(r[5]).trim();
        if (uname !== "") {
           activeUsernames.push(uname);
           if(token) validTokens.push(token);
        }
      });
    }

    const users = userSheet.getDataRange().getValues().slice(1).map(r => {
      const isOnline = activeUsernames.includes(String(r[1]).trim());
      const hasBioData = String(r[7]).trim() !== "";
      return { id: r[0], username: r[1], role: r[3], name: r[4], status: isOnline ? 'Online' : 'Offline', bioStatus: r[8] || 'Enabled', dbAccess: r[9] || '', forceReset: r[10] || '', hasBio: hasBioData };
    });
    
    let approvals = [];
    if (appSheet && appSheet.getLastRow() > 1) {
        approvals = appSheet.getDataRange().getValues().slice(1)
            .filter(r => r[4] === "Pending")
            .map(r => ({ id: r[0], username: r[1], type: r[2], hash: r[3], status: r[4], date: r[5] }));
    }

    const logs = logSheet && logSheet.getLastRow() > 1 ? logSheet.getDataRange().getValues().slice(1).reverse() : [];
    
    const pages = pageSheet && pageSheet.getLastRow() > 1 ? pageSheet.getDataRange().getValues().slice(1).map(r => ({ id: r[0], title: r[1], url: r[2], allowed: r[3], status: r[4] || 'Visible' })) : [];
    
    let activeUsers = users.filter(u => u.status === 'Online');
    const keyCount = secSheet ? Math.max(0, secSheet.getLastRow() - 1) : 0;
    
    return ContentService.createTextOutput(JSON.stringify({
      users, logs, pages, approvals, active: activeUsers, validTokens: validTokens, maintenance: maint, passkeyLogin: passkeyLogin, keyCount: keyCount
    })).setMimeType(ContentService.MimeType.JSON);
    
  } catch(err) {
    return ContentService.createTextOutput("ERROR: " + err.message);
  }
}
