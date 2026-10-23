// Small built-in word lists. Real cracking tools use lists with millions of
// entries (e.g. rockyou.txt); these are enough to demonstrate the idea.

// Most common passwords, in rank order (position 1 = most common).
const COMMON_PASSWORDS = [
  '123456', 'password', '123456789', '12345678', '12345', 'qwerty', '1234567',
  '111111', '123123', 'abc123', '1234567890', 'password1', '1234', 'iloveyou',
  '000000', 'qwerty123', '1q2w3e4r', 'admin', 'qwertyuiop', '654321', '555555',
  'lovely', '7777777', 'welcome', '888888', 'princess', 'dragon', '123321',
  'sunshine', 'monkey', 'football', 'letmein', 'shadow', 'master', '666666',
  'baseball', 'superman', 'michael', '696969', 'trustno1', 'batman', 'starwars',
  'hello', 'freedom', 'whatever', 'qazwsx', 'ninja', 'mustang', 'passw0rd',
  'password123', 'charlie', 'donald', 'login', 'access', 'flower', 'loveme',
  'zaq1zaq1', 'hunter', 'cheese', 'killer', 'soccer', 'ashley', 'bailey',
  'jordan', 'harley', 'ranger', 'buster', 'thomas', 'tigger', 'robert', 'daniel',
  'hockey', 'george', 'computer', 'michelle', 'jennifer', 'pepper', 'matrix',
  'maggie', 'ginger', 'summer', 'internet', 'secret', 'samsung', 'liverpool',
  'chelsea', 'arsenal', 'india', 'cricket', 'india123', 'pokemon', 'minecraft',
  'google', 'test', 'test123', 'changeme', 'default', 'root', 'guest', 'qwerty1',
  'asdfgh', 'asdfghjkl', 'zxcvbnm', '112233', '121212', '987654321', 'aa123456',
  'abcd1234', '1qaz2wsx', 'iloveyou1', 'sairam', 'krishna', 'omsairam',
  'welcome1', 'admin123', 'password1234', 'qwerty12345',
];

// Common English words and names that people build passwords from.
const DICTIONARY_WORDS = [
  'pass', 'word', 'love', 'admin', 'user', 'super', 'star', 'wars', 'winter',
  'spring', 'autumn', 'college', 'school', 'student', 'apple', 'orange',
  'banana', 'mango', 'tiger', 'lion', 'eagle', 'angel', 'heaven', 'money',
  'happy', 'lucky', 'family', 'friend', 'black', 'white', 'green', 'blue',
  'purple', 'silver', 'golden', 'diamond', 'magic', 'power', 'king', 'queen',
  'prince', 'baby', 'sweet', 'honey', 'cookie', 'chocolate', 'coffee', 'pizza',
  'music', 'guitar', 'dance', 'game', 'gamer', 'player', 'phone', 'mobile',
  'hacker', 'cyber', 'secure', 'security', 'system', 'server', 'network',
  'office', 'company', 'manager', 'mother', 'father', 'sister', 'brother',
  'rahul', 'priya', 'amit', 'sneha', 'rohan', 'anjali', 'john', 'david',
  'james', 'sarah', 'jessica', 'mumbai', 'delhi', 'pune', 'bangalore',
  'london', 'paris', 'dragon', 'monkey', 'shadow', 'master', 'hunter',
  'killer', 'summer', 'flower', 'sunshine', 'princess', 'football', 'soccer',
  'cricket', 'india', 'welcome', 'hello', 'secret', 'login', 'access',
  'freedom', 'whatever', 'computer', 'internet', 'password', 'qwerty',
];

if (typeof module !== 'undefined') module.exports = { COMMON_PASSWORDS, DICTIONARY_WORDS };
