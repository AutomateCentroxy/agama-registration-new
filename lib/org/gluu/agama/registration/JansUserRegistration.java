package org.gluu.agama.registration;

import io.jans.as.common.model.common.User;
import io.jans.as.common.service.common.UserService;
import io.jans.orm.exception.operation.EntryNotFoundException;
import io.jans.service.cdi.util.CdiUtil;
import io.jans.util.StringHelper;

import org.gluu.agama.user.UserRegistration;
import io.jans.agama.engine.script.LogUtils;
import org.gluu.agama.sms.OTPService;
import org.gluu.agama.smtp.EmailService;
import org.gluu.agama.smtp.jans.model.ContextData;

import java.security.SecureRandom;
import java.util.*;
import java.util.regex.Pattern;

public class JansUserRegistration extends UserRegistration {

    private static final String MAIL = "mail";
    private static final String UID = "uid";
    private static final String DISPLAY_NAME = "displayName";
    private static final String GIVEN_NAME = "givenName";
    private static final String PASSWORD = "userPassword";
    private static final String INUM_ATTR = "inum";
    private static final String USER_STATUS = "jansStatus";
    private static final String PHONE = "telephoneNumber";
    private static final String COUNTRY = "residenceCountry";
    private static final String REFERRAL = "referralCode";

    private static final SecureRandom RAND = new SecureRandom();
    private static JansUserRegistration INSTANCE = null;

    private final Map<String, String> emailOtpStore = new HashMap<>();
    private final OTPService otpService = OTPService.getInstance(new HashMap<>());
    private final EmailService emailService = EmailService.getInstance();

    public JansUserRegistration() {}

    public static synchronized JansUserRegistration getInstance() {
        if (INSTANCE == null)
            INSTANCE = new JansUserRegistration();
        return INSTANCE;
    }

    public boolean passwordPolicyMatch(String userPassword) {
        String regex = "^(?=.*[!@#$^&*])[A-Za-z0-9!@#$^&*]{6,}$";
        return Pattern.compile(regex).matcher(userPassword).matches();
    }

    public boolean usernamePolicyMatch(String userName) {
        return Pattern.compile("^[A-Za-z]+$").matcher(userName).matches();
    }

    public boolean checkIfUserExists(String username, String email) {
        return !getUserEntityByUsername(username).isEmpty() || !getUserEntityByMail(email).isEmpty();
    }

    public boolean matchPasswords(String pwd1, String pwd2) {
        return pwd1 != null && pwd1.equals(pwd2);
    }

    public String sendSmsOtp(String username) {
        return otpService.sendOTPCode(username);
    }

    public boolean validateSmsOtp(String username, String otp) {
        return otpService.validateOTPCode(username, otp);
    }

    public boolean registerPhone(String username, String phoneNumber) {
        return otpService.registerPhone(username, phoneNumber);
    }

    public boolean sendEmailOtp(String email) {
        String otp = generateOtp();
        emailOtpStore.put(email, otp);
        LogUtils.log("Sent Email OTP % to %", otp, email);

        ContextData context = new ContextData();
        context.setTimeZone("Asia/Kolkata"); // Set as per your requirement
        context.setDevice("Web Browser");
        context.setLocation("India");

        emailService.sendEmail(email, context);
        return true;
    }

    public boolean validateEmailOtp(String email, String otp) {
        String sentOtp = emailOtpStore.get(email);
        return otp != null && otp.equals(sentOtp);
    }

    public String addNewUser(Map<String, String> profile) throws Exception {
        Set<String> attributes = Set.of("uid", "mail", "displayName", "givenName", "sn", "userPassword", PHONE, COUNTRY, REFERRAL);

        User user = new User();
        attributes.forEach(attr -> {
            String val = profile.get(attr);
            if (StringHelper.isNotEmpty(val)) {
                user.setAttribute(attr, val);
            }
        });

        UserService userService = CdiUtil.bean(UserService.class);
        user = userService.addUser(user, true);

        if (user == null) {
            throw new EntryNotFoundException("User creation failed");
        }

        return getSingleValuedAttr(user, INUM_ATTR);
    }

    public Map<String, String> getUserEntityByMail(String email) {
        User user = getUser(MAIL, email);
        return extractUserInfo(user, email);
    }

    public Map<String, String> getUserEntityByUsername(String username) {
        User user = getUser(UID, username);
        return extractUserInfo(user, null);
    }

    private Map<String, String> extractUserInfo(User user, String fallbackEmail) {
        boolean found = user != null;
        String ref = fallbackEmail != null ? fallbackEmail : user != null ? user.getUserId() : "unknown";
        LogUtils.log("User lookup for %: %", ref, found ? "FOUND" : "NOT FOUND");

        if (!found) return new HashMap<>();

        Map<String, String> userMap = new HashMap<>();
        userMap.put(UID, getSingleValuedAttr(user, UID));
        userMap.put(INUM_ATTR, getSingleValuedAttr(user, INUM_ATTR));
        userMap.put("name", Optional.ofNullable(getSingleValuedAttr(user, GIVEN_NAME))
                .orElseGet(() -> getSingleValuedAttr(user, DISPLAY_NAME)));
        userMap.put("email", Optional.ofNullable(getSingleValuedAttr(user, MAIL)).orElse(fallbackEmail));

        return userMap;
    }

    private String getSingleValuedAttr(User user, String attribute) {
        if (user == null) return null;
        if (attribute.equals(UID)) {
            return user.getUserId();
        }
        Object val = user.getAttribute(attribute, true, false);
        return val != null ? val.toString() : null;
    }

    private static User getUser(String attributeName, String value) {
        UserService userService = CdiUtil.bean(UserService.class);
        return userService.getUserByAttribute(attributeName, value, true);
    }

    private String generateOtp() {
        int otp = 100000 + RAND.nextInt(900000);
        return String.valueOf(otp);
    }
}
