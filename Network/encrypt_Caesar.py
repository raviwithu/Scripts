

alphabe = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
key = 3
original_message = 'texq qeb c..h'
encrypted_message = ''

original_message = original_message.upper()
print(original_message)

for character in original_message:
    new_character = ''
    if character in alphabe:
        original_position = alphabe.find(character)
        new_position = original_position + key

        if new_position > len(alphabe)-1:
            new_position = original_position + key - len(alphabe)
        new_character = alphabe[new_position]
    else:
        new_character = character
    encrypted_message = encrypted_message + new_character

print(encrypted_message)






