#define _GNU_SOURCE
#include <openssl/md5.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <pthread.h>

// Each username max length is 64 characters
#define MAX_USERNAME_LENGTH 64
// Each password has 6 characters
#define PASSWORD_LENGTH 6
#define TOTAL_THREADS 4
// Total of passwords in the set is pow(26,6)
#define TOTAL_PASSWORDS 308915776
/************************* Part A *************************/
/********************* Parts B & C ************************/

/*
Parameters:
   *possible_guess is candidate password
   *input_hash : the hashed version produced 
*/
int check_hash_password(char *output, char *possible_guess, char *input_hash)
{
  // Take our candidate password and hash it using MD5
  // char *candidate_passwd = "psswwd";
  //char *candidate_passwd = possible_guess;                                                //< This variable holds the password we are trying
  uint8_t candidate_hash[MD5_DIGEST_LENGTH]; //< This will hold the hash of the candidate password

  MD5((unsigned char *)possible_guess, strlen(possible_guess), candidate_hash); //< Do the hash
  if (strcmp("psswrd", possible_guess) == 0)
  {
    printf("psswrd found\n");
  }

  // Now check if the hash of the candidate password matches the input hash
  if (memcmp((uint8_t *)input_hash, candidate_hash, MD5_DIGEST_LENGTH) == 0)
  {
    // Match! Copy the password to the output and return 0 (success)
    strncpy(output, possible_guess, PASSWORD_LENGTH + 1);
    printf("matched hash \n");
    return 0;
  }
  else
  {
    // No match. Return -1 (failure)
    return -1;
  }
}

int generate_all_permutations(size_t index, char *possible_guess, char *output, char *hash)
{

  // Base Case, when we reach index = 6, we completed one guess
  if (index == 6)
  {
    // we call check_hash_password to check if there is a hashed version of this password
    // printf("base case, guess = %s\n", possible_guess);
    return check_hash_password(output, possible_guess, hash);
    //return result;
  }
  else
  {
    // We start building up the strings of 6 characters
    // Given the current index, we try to put 26 characters in this index, and for each of this character
    // We call the recursion again with the incremented index
    int result = 0;
    for (int i = 'z'; i >= 'a'; i--)
    {
      possible_guess[index] = (char)i;
      result = generate_all_permutations(index + 1, possible_guess, output, hash);
      if (result != -1)
        return result;
    }
    return -1;
  }
}

/**
 * Find a six character lower-case alphabetic password that hashes
 * to the given hash value. Complete this function for part A of the lab.
 *
 * \param input_hash  An array of MD5_DIGEST_LENGTH bytes that holds the hash of a password
 * \param output      A pointer to memory with space for a six character password + '\0'
 * \returns           0 if the password was cracked. -1 otherwise.
 */
int crack_single_password(uint8_t *input_hash, char *output)
{

  // Generate all possible candidates password
  // For eeach candidate, we call check_hash_password to see if there is a matching hash
  // If yes, return 0, else return -1

  // Initialize an index to start building the candidate password
  int index = 0;
  char possible_guess[7] = "";
  printf("output before = %s\n", output);
  int found = generate_all_permutations(index, possible_guess, output, (char *)input_hash);
  printf("output after = %s\n", output);
  printf("found = %d\n", found);
  return found;
}

/********************* Parts B & C ************************/
/*********************Global Variables***********************/

int passwords_cracked = 0;
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
/*********************************************/

// Struct to store username and password data
typedef struct user_password_object
{
  char username[MAX_USERNAME_LENGTH + 1];
  uint8_t password_md5[MD5_DIGEST_LENGTH + 1];
  bool cracked;
  struct user_password_object *next;
} user_password_t;

/**
 * This struct is the root of the data structure that will hold users and hashed passwords.
 * This could be any type of data structure you choose: list, array, tree, hash table, etc.
 * Implement this data structure for part B of the lab.
 */
typedef struct password_set
{
  user_password_t *head;
  int number_of_users;
} password_set_t;

// Struct to store thread information

typedef struct thread_info
{
  int thread_index;
  int starting_point;
  long total_read;
  password_set_t *passwords;
} thread_info_t;

/**
 * Initialize a password set.
 * Complete this implementation for part B of the lab.
 *
 * \param passwords  A pointer to allocated memory that will hold a password set
 */
void init_password_set(password_set_t *passwords)
{
  passwords->head = NULL;
  passwords->number_of_users = 0;
}

/**
 * Add a password to a password set
 * Complete this implementation for part B of the lab.
 *
 * \param passwords   A pointer to a password set initialized with the function above.
 * \param username    The name of the user being added. The memory that holds this string's
 *                    characters will be reused, so if you keep a copy you must duplicate the
 *                    string. I recommend calling strdup().
 * \param password_hash   An array of MD5_DIGEST_LENGTH bytes that holds the hash of this user's
 *                        password. The memory that holds this array will be reused, so you must
 *                        make a copy of this value if you retain it in your data structure.
 */
void add_password(password_set_t *passwords, char *username, uint8_t *password_hash)
{
  //add_password(&passwords, username, password_hash);
  // Add the provided user and password hash to your set of passwords

  // Create a new object to hold the new pair of data
  user_password_t *new_pair = (user_password_t *)malloc(sizeof(user_password_t));
  new_pair->cracked = false;
  memcpy(new_pair->username, username, MAX_USERNAME_LENGTH);
  memcpy(new_pair->password_md5, password_hash, sizeof(uint8_t) * MD5_DIGEST_LENGTH);

  // Next we add this new object to the list of user password objects
  // This takes care of both cases when passwords->head is NULL or not NULL
  new_pair->next = passwords->head;
  passwords->head = new_pair;
  passwords->number_of_users++;
}

bool matched_hash(uint8_t current_pass[], uint8_t hashed_candidate[])
{
  return memcmp(current_pass, hashed_candidate, MD5_DIGEST_LENGTH) == 0;
}

void *thread_crack_password(void *args)
{

  thread_info_t *thread_information = (thread_info_t *)args;
  // Get the passwords set
  password_set_t *passwords = thread_information->passwords;
  // Get the starting point to check password in the password space
  int starting_point = thread_information->starting_point;
  // Get the total number of passwords have to check
  long total_read = thread_information->total_read;

  // Initialize a string to hold candidate password
  char candidate_password[7] = "";
  int tmp = starting_point;
  int password_counter = 0;
  while (password_counter < total_read && passwords_cracked <= passwords->number_of_users)
  {
    // Reset tmp to starting point
    tmp = starting_point;
    // Generate a candidate password
    // Start from the last character at index 5 back to character
    // at index 0, we start putting in 26 characters from a->z at each index,
    // holding other indices constant to generate strings such as
    // aaaaaa, aaaaab, aaaaac,...aaaaaz and so on
    for (int i = 5; i >= 0; i--)
    {
      // We add a and offset (tmp % 26) to generate the character
      // such as a, b, c,...z
      candidate_password[i] = (char)'a' + (tmp % 26);
      tmp = tmp / 26;
    }
    // Checking password_hash
    // hashed_candidate hold the hash value of candidate_password
    uint8_t hashed_candidate[MD5_DIGEST_LENGTH];
    MD5((unsigned char *)candidate_password, strlen(candidate_password), hashed_candidate); // Do the hash

    // Iterate through the password sets to see if hashed_candidate matches any hashes stored from usernames
    user_password_t *cursor = passwords->head;
    while (cursor != NULL)
    {
      // If the current username's password is already cracked, then skip and just move the cursor
      // Else if it is not cracked, we compare the hashes value
      if (!cursor->cracked)
      {
        // If the hash is matched
        if (matched_hash(cursor->password_md5, hashed_candidate))
        {
          // We update the field cracked inside current pair
          pthread_mutex_lock(&lock);
          cursor->cracked = true;
          // Increment number of passwords cracked
          passwords_cracked++;
          pthread_mutex_unlock(&lock);
          // Printout the username and password
          printf("%s %s\n", cursor->username, candidate_password);
          break;
        }
      }
      // Move the cursor
      cursor = cursor->next;
    }
    starting_point++;
    password_counter++;
  }
  return NULL;
}

/**
 * Crack all of the passwords in a set of passwords. The function should print the username
 * and cracked password for each user listed in passwords, separated by a space character.
 * Complete this implementation for part B of the lab.
 *
 * \returns The number of passwords cracked in the list
 */
int crack_password_list(password_set_t *passwords)
{

  // Intialize an array of 4 threads
  pthread_t threads[TOTAL_THREADS];
  // Initialize an array to hold thread information
  thread_info_t arguments_array[TOTAL_THREADS];
  long total_read = TOTAL_PASSWORDS / TOTAL_THREADS;

  for (int i = 0; i < TOTAL_THREADS; i++)
  {
    arguments_array[i].thread_index = i;
    arguments_array[i].passwords = passwords;
    arguments_array[i].starting_point = i * total_read;
    arguments_array[i].total_read = total_read;
    pthread_create(&(threads[i]), NULL, thread_crack_password, &(arguments_array[i]));
  }
  for (int i = 0; i < TOTAL_THREADS; i++)
  {
    pthread_join(threads[i], NULL);
  }

  return passwords_cracked;
}

/******************** Provided Code ***********************/

/**
 * Convert a string representation of an MD5 hash to a sequence
 * of bytes. The input md5_string must be 32 characters long, and
 * the output buffer bytes must have room for MD5_DIGEST_LENGTH
 * bytes.
 *
 * \param md5_string  The md5 string representation
 * \param bytes       The destination buffer for the converted md5 hash
 * \returns           0 on success, -1 otherwise
 */
int md5_string_to_bytes(const char *md5_string, uint8_t *bytes)
{
  // Check for a valid MD5 string
  if (strlen(md5_string) != 2 * MD5_DIGEST_LENGTH)
    return -1;

  // Start our "cursor" at the start of the string
  const char *pos = md5_string;

  // Loop until we've read enough bytes
  for (size_t i = 0; i < MD5_DIGEST_LENGTH; i++)
  {
    // Read one byte (two characters)
    int rc = sscanf(pos, "%2hhx", &bytes[i]);
    if (rc != 1)
      return -1;

    // Move the "cursor" to the next hexadecimal byte
    pos += 2;
  }

  return 0;
}

void print_usage(const char *exec_name)
{
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "  %s single <MD5 hash>\n", exec_name);
  fprintf(stderr, "  %s list <password file name>\n", exec_name);
}

void free_passwords_set(password_set_t *passwords)
{
  user_password_t *cursor = passwords->head;
  user_password_t *temp = NULL;
  while (cursor != NULL)
  {
    temp = cursor;
    cursor = cursor->next;
    free(temp);
  }
}

int main(int argc, char **argv)
{
  if (argc != 3)
  {
    print_usage(argv[0]);
    exit(1);
  }

  if (strcmp(argv[1], "single") == 0)
  {
    // The input MD5 hash is a string in hexadecimal. Convert it to bytes.
    uint8_t input_hash[MD5_DIGEST_LENGTH];
    if (md5_string_to_bytes(argv[2], input_hash))
    {
      fprintf(stderr, "Input has value %s is not a valid MD5 hash.\n", argv[2]);
      exit(1);
    }

    // Now call the crack_single_password function
    char result[7];
    if (crack_single_password(input_hash, result))
    {
      printf("No matching password found.\n");
    }
    else
    {
      printf("%s\n", result);
    }
  }
  else if (strcmp(argv[1], "list") == 0)
  {
    // Make and initialize a password set
    password_set_t passwords;
    init_password_set(&passwords);

    // Open the password file
    FILE *password_file = fopen(argv[2], "r");
    if (password_file == NULL)
    {
      perror("opening password file");
      exit(2);
    }

    int password_count = 0;

    // Read until we hit the end of the file
    while (!feof(password_file))
    {
      // Make space to hold the username
      char username[MAX_USERNAME_LENGTH];

      // Make space to hold the MD5 string
      char md5_string[MD5_DIGEST_LENGTH * 2 + 1];

      // Make space to hold the MD5 bytes
      uint8_t password_hash[MD5_DIGEST_LENGTH];

      // Try to read. The space in the format string is required to eat the newline
      if (fscanf(password_file, "%s %s ", username, md5_string) != 2)
      {
        fprintf(stderr, "Error reading password file: malformed line\n");
        exit(2);
      }

      // Convert the MD5 string to MD5 bytes in our new node
      if (md5_string_to_bytes(md5_string, password_hash) != 0)
      {
        fprintf(stderr, "Error reading MD5\n");
        exit(2);
      }

      // Add the password to the password set
      add_password(&passwords, username, password_hash);
      password_count++;
    }

    // Now run the password list cracker
    int cracked = crack_password_list(&passwords);

    printf("Cracked %d of %d passwords.\n", cracked, password_count);
    // Free passwords
    free_passwords_set(&passwords);
  }
  else
  {
    print_usage(argv[0]);
    exit(1);
  }

  return 0;
}
