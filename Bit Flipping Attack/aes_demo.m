% Initialization
[s_box, inv_s_box, w, poly_mat, inv_poly_mat] = aes_init;

% Define an arbitrary series of 16 plaintext bytes 
% in hexadecimal (string) representation
s = '{T:40C, SOC:65%}';
plaintext_hex = {'7B' '54' '4D' '50' '3A' '34' '30' '2C' ...
                 '20' '53' '4F' '43' '3A' '36' '35' '7D'};

% Convert plaintext from hexadecimal (string) to decimal representation
plaintext = hex2dec(plaintext_hex);

% Convert the plaintext to ciphertext
ciphertext = cipher(double(s), w, s_box, poly_mat, 1);

% Convert the ciphertext back to plaintext
re_plaintext = inv_cipher(ciphertext, w, inv_s_box, inv_poly_mat, 1);

disp(s);
disp(char(re_plaintext));
disp(char(ciphertext));