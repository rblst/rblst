/*-------------------------------------------------------------------------
 *
 * passwordcheck_with_params.c
 *
 *
 * Portions Copyright (c) 2009-2018, PostgreSQL Global Development Group
 * Author: Laurenz Albe <laurenz.albe@wien.gv.at>
 *
 * Portions Copyright (c) 2020-2021, Webvalto Kft.
 * Author: Tamas Rebeli-Szabo <trebeli@webvalto.hu>
 *
 * NOTE:
 * This is an extended version of the original passwordcheck contrib module.
 * GUC variables have been added for parametrizability.
 *
 *-------------------------------------------------------------------------
 */

 #include "postgres.h"

 #include <ctype.h>

 #ifdef USE_CRACKLIB
 #include <crack.h>
 #endif

 #include "commands/user.h"
 #include "libpq/crypt.h"
 #include "fmgr.h"
 #include "utils/guc.h"

 PG_MODULE_MAGIC;


/* Define characters classes. */

#define UPPER_CASE_CHARS "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
#define LOWER_CASE_CHARS "abcdefghijklmnopqrstuvwxyz"
#define DIGIT_CHARS      "0123456789"
#define SPECIAL_CHARS    "<>,?;.:/!§ù%*µ^¨$£²&é~\"#'{([-|è`_\\ç^à@)]°=}+"


/*
 * GUC variable for passwordcheck.min_length.
 *
 * Specifies the required minimum number of characters in the password.
 * If the password contains fewer characters, the check fails.
 */

int pwchkMinLength = 8;


/*
 * GUC variable for passwordcheck.max_length.
 *
 * Specifies the allowed maximum number of characters in the password.
 * If the password contains more characters, the check fails.
 */

int pwchkMaxLength = 128;


/*
 * GUC variable for passwordcheck.min_lower_char.
 *
 * Specifies the required minimum number of lower-case characters in the password.
 * If the password contains fewer lower-case characters, the check fails.
 */

int pwchkMinLowerChar = 1;


/*
 * GUC variable for passwordcheck.min_upper_char.
 *
 * Specifies the required minimum number of upper-case characters in the password.
 * If the password contains fewer upper-case characters, the check fails.
 */

int pwchkMinUpperChar = 1;


/*
 * GUC variable for passwordcheck.min_digit_char.
 *
 * Specifies the required minimum number of digit characters in the password.
 * If the password contains fewer digit characters, the check fails.
 */

int pwchkMinDigitChar = 1;


/*
 * GUC variable for passwordcheck.min_special_char.
 *
 * Specifies the required minimum number of special characters in the password.
 * A special character is one of: <>,?;.:/!§ù%*µ^¨$£²&é~\"#'{([-|è`_\\ç^à@)]°=}+.
 * If the password contains fewer special characters, the check fails.
 */

int pwchkMinSpecialChar = 1;


/*
 * GUC variable for passwordcheck.disallowed_chars.
 *
 * Specifies characters that are diasallowed in the password.
 * Charaters must form a continuous string with no separator.
 * If the password contains any of the characters, the check fails.
 */

char *pwchkDisallowedChars = "";


/*
 * GUC variable for passwordcheck.use_cracklib.
 *
 * Specifies whether to use cracklib for quality and dictionary-based check.
 * If the password does not meet default cracklib quality criteria, the check fails.
 * If the password matches a dictionary entry, the check fails.
 * If module is not compiled with cracklib, the parameter is ignored.
 */

bool pwchkUseCracklib = false;




extern void _PG_init(void);

/*
 * check_password
 *
 * Performs checks on an encrypted or unencrypted password and
 * ereport's if not acceptable.
 *
 * Function parameters:
 *  username: name of role being created or changed
 *  password: new password (possibly already encrypted)
 *  password_type: PASSWORD_TYPE_* code, to indicate if the password is
 *			in plaintext or encrypted form.
 *  validuntil_time: password expiration time, as a timestamptz Datum
 *  validuntil_null: true if password expiration time is NULL
 *
 * This implementation doesn't pay any attention to the password
 * expiration time, but you might wish to insist that it be non-null and
 * not too far in the future.
 */
static void
check_password(const char *username,
			   const char *shadow_pass,
			   PasswordType password_type,
			   Datum validuntil_time,
			   bool validuntil_null)
{
	if (password_type != PASSWORD_TYPE_PLAINTEXT)
	{
		/*
		 * Unfortunately we cannot perform exhaustive checks on encrypted
		 * passwords - we are restricted to guessing. (Alternatively, we could
		 * insist on the password being presented non-encrypted, but that has
		 * its own security disadvantages.)
		 *
		 * We only check for username = password.
		 */
		char	   *logdetail;

		if (plain_crypt_verify(username, shadow_pass, username, &logdetail) == STATUS_OK)
			ereport(ERROR,
					(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
					 errmsg("password must not equal user name")));
	}
	else
	{
		/*
		 * For unencrypted passwords we can perform better checks.
		 */
		const char *password = shadow_pass;
		int			pwdlen = strlen(password);
		int			i;
		int		  num_upper,
            num_lower,
            num_digit,
            num_special,
            num_disallowed;
    const char *cracklib_reason;

    /* Enforce minimum password length constraint. */

    if (pwdlen < pwchkMinLength)
      ereport(ERROR,
          (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
           errmsg("password is too short, it must be at least %d characters long",pwchkMinLength)));


    /* Enforce maximum password length constraint. */

     if (pwdlen > pwchkMaxLength)
      ereport(ERROR,
          (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
          errmsg("password is too long, it must not be longer than %d characters",pwchkMaxLength)));


    /* Enforce character class constraints
       and disallowed characters constraint.*/

    num_upper      = 0;
    num_lower      = 0;
    num_digit      = 0;
    num_special    = 0;
    num_disallowed = 0;

    for (i = 0; i < pwdlen; i++)
    {
       /* Count lower-case characters.*/
       if (strchr(LOWER_CASE_CHARS, password[i]) != NULL) {
         num_lower++;
       }

       /* Count upper-case characters.*/
       if (strchr(UPPER_CASE_CHARS, password[i]) != NULL) {
         num_upper++;
       }

       /* Count digit characters.*/
       if (strchr(DIGIT_CHARS, password[i]) != NULL) {
         num_digit++;
       }

       /* Count special characters.*/
       if (strchr(SPECIAL_CHARS, password[i]) != NULL) {
           num_special++;
       }
       /* Count disallowed characters.*/
       if (strchr(pwchkDisallowedChars, password[i]) != NULL) {
           num_disallowed++;
       }

    }

    if (num_lower < pwchkMinLowerChar) {
      ereport(ERROR,
            (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
             errmsg("password must contain at least %d lower-case characters",pwchkMinLowerChar)));
    }

    if (num_upper < pwchkMinUpperChar) {
      ereport(ERROR,
            (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
             errmsg("password must contain at least %d upper-case characters",pwchkMinUpperChar)));
    }

    if (num_digit < pwchkMinDigitChar) {
      ereport(ERROR,
            (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
             errmsg("password must contain at least %d digits",pwchkMinDigitChar)));
    }

    if (num_special < pwchkMinSpecialChar) {
      ereport(ERROR,
            (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
             errmsg("password must contain at least %d special characters",pwchkMinSpecialChar)));
    }

    if (num_disallowed > 0) {
      ereport(ERROR,
            (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
             errmsg("password must not contain any of the following characters:%s",pwchkDisallowedChars)));
    }


 #ifdef USE_CRACKLIB
	 	/* Call cracklib to check password.*/
     if (pwchkUseCracklib) {
       if ((cracklib_reason=FascistCheck(password, CRACKLIB_DICTPATH)))
		  	 ereport(ERROR,
		  		 	(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
		  			  errmsg("password is easily cracked: %s",cracklib_reason)));
      }
 #endif
   }

/* All checks passed, password is OK. */
}



/*
 * Module initialization function.
 * Define GUC variables and install hooks upon module load.
 */
void
_PG_init(void)
{

   /* Define parameter passwordcheck.min_length. */

   DefineCustomIntVariable(
         "passwordcheck.min_length",

         "Minimum number of characters in the password.",

         "Specifies the required minimum number of characters in the password."
         "If the password contains fewer characters, the check fails.",

         &pwchkMinLength,
 	       8,
 	       0,
 	       128,
         PGC_SUSET,
         GUC_NOT_IN_SAMPLE,
         NULL, NULL, NULL);


   /* Define parameter passwordcheck.max_length. */

   DefineCustomIntVariable(
         "passwordcheck.max_length",

         "Maximum number of characters in the password.",

         "Specifies the allowed maximum number of characters in the password."
         "If the password contains more characters, the check fails.",

         &pwchkMaxLength,
 	       32,
 	       0,
 	       128,
         PGC_SUSET,
         GUC_NOT_IN_SAMPLE,
         NULL, NULL, NULL);



  /* Define parameter passwordcheck.min_lower_char. */

  DefineCustomIntVariable(
         "passwordcheck.min_lower_char",

         "Minimum number of lower-case characters in the password.",

         "Specifies the required minimum number of lower-case characters in the password."
         "If the password contains fewer lower-case characters, the check fails.",

         &pwchkMinLowerChar,
 	       1,
 	       0,
 	       64,
         PGC_SUSET,
         GUC_NOT_IN_SAMPLE,
         NULL, NULL, NULL);

  /* Define parameter passwordcheck.min_upper_char. */

  DefineCustomIntVariable(
         "passwordcheck.min_upper_char",

         "Minimum number of upper-case characters in the password.",

         "Specifies the required minimum number of upper-case characters in the password."
         "If the password contains fewer upper-case characters, the check fails.",

         &pwchkMinUpperChar,
       	 1,
       	 0,
       	 64,
         PGC_SUSET,
         GUC_NOT_IN_SAMPLE,
         NULL, NULL, NULL);


  /* Define parameter passwordcheck.min_digit_char. */

  DefineCustomIntVariable(
         "passwordcheck.min_digit_char",

         "Minimum number of digit characters in the password.",

         "Specifies the required minimum number of digit characters in the password."
         "If the password contains fewer digit characters, the check fails.",

         &pwchkMinDigitChar,
       	 1,
       	 0,
       	 64,
         PGC_SUSET,
         GUC_NOT_IN_SAMPLE,
         NULL, NULL, NULL);


  /* Define parameter passwordcheck.min_special_char. */

  DefineCustomIntVariable(
         "passwordcheck.min_special_char",

         "Minimum number of special characters in the password.",

         "Specifies the required minimum number of special characters in the password."
         "A special character is one of: <>,?;.:/!§ù%*µ^¨$£²&é~\"#'{([-|è`_\\ç^à@)]°=}+."
         "If the password contains fewer special characters, the check fails.",

         &pwchkMinSpecialChar,
 	       1,
 	       0,
 	       64,
         PGC_SUSET,
         GUC_NOT_IN_SAMPLE,
         NULL, NULL, NULL);


  /* Define parameter passwordcheck.disallowed_chars. */

  DefineCustomStringVariable(
         "passwordcheck.disallowed_chars",

         "List of forbidden characters in the password.",

         "Specifies characters that are diasallowed in the password."
         "Charaters must form a continuous string with no separator."
         "If the password contains any of the characters, the check fails.",

         &pwchkDisallowedChars,
         "",
         PGC_SUSET,
         GUC_NOT_IN_SAMPLE,
         NULL, NULL, NULL);


  /* Define parameter passwordcheck.use_cracklib. */

  DefineCustomBoolVariable(
         "passwordcheck.use_cracklib",

         "Use cracklib for password check.",

         "Specifies whether to use cracklib for quality and dictionary-based check."
         "If the password does not meet default cracklib quality criteria, the check fails."
         "If module is not compiled with cracklib, the parameter is ignored.",

         &pwchkUseCracklib,
         false,
         PGC_SUSET,
         GUC_NOT_IN_SAMPLE,
         NULL, NULL, NULL);


	/* Activate password checks when the module is loaded. */
	check_password_hook = check_password;
}
