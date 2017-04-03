"""PASSWORD CHECKER by s3icc0

based on http://www.passwordmeter.com/

Purpose:
Type in the password you want to analyse and understand its strength or
weakness.
"""

# ------------------------------------------------------------------------------
# ------------------------------ SYSTEM SETUP ----------------------------------
# ------------------------------------------------------------------------------


import os
import math


def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')


def set_window_size(cols, lines):
    os.system('mode con: cols={0} lines={1}'.format(cols, lines))


"""Windows Console size variables"""
win_console_width = 180
win_console_height = 50


# ------------------------------------------------------------------------------
# ------------------------------ CALCULATIONS ----------------------------------
# ------------------------------------------------------------------------------


def pwd_as_list():

    for char in password:
        pwd_list.append(char)


def pwd_length():
    count = len(pwd_list)

    ns['len'] = count

    score = count * 4
    scores['len'] = score


def pwd_upcase():
    count = 0

    for i in pwd_list:
        if i.isupper():
            count += 1
    ns['upc'] = count

    score = (ns['len'] - count) * 2
    scores['upc'] = score


def pwd_lowcase():
    count = 0

    for i in pwd_list:
        if i.islower():
            count += 1

    ns['lowc'] = count

    score = (ns['len'] - ns['lowc']) * 2
    scores['lowc'] = score


def pwd_numbers():
    count = 0

    for i in pwd_list:
        if i.isdigit():
            count += 1

    ns['nums'] = count

    score = ns['nums'] * 4
    scores['nums'] = score


def pwd_symbols():
    count = 0

    for i in pwd_list:
        if not i.isalnum():
            count += 1

    ns['syms'] = count

    score = ns['syms'] * 6
    scores['syms'] = score


def pwd_mid_nr_or_sym():
    count = 0

    for i in pwd_list[1:ns['len'] - 1]:
        if not i.isalnum():
            count += 1
        elif i.isdigit():
            count += 1

    ns['mid'] = count

    score = ns['mid'] * 2
    scores['mid'] = score


def pwd_requirements():
    count = 0
    count_list = [
        ns['len'] >= 8,
        ns['upc'],
        ns['lowc'],
        ns['nums'],
        ns['syms']
    ]

    for i in count_list:
        if i >= 1:
            count += 1

    ns['reqr'] = count

    score = ns['reqr'] * 2
    scores['reqr'] = score


def pwd_only_letters():
    count = 0

    for i in pwd_list:
        if i.isalpha():
            count += 1

    if count == ns['len']:
        ns['let_only'] = count
    else:
        ns['let_only'] = 0

    scores['let_only'] = ns['let_only']


def pwd_only_numbers():
    count = 0

    for i in pwd_list:
        if i.isdigit():
            count += 1

    if count == ns['len']:
        ns['num_only'] = count
    else:
        ns['num_only'] = 0

    scores['num_only'] = ns['num_only']


def pwd_rept_chars():
    used_chars = {}
    norep_chars = []

    for i in pwd_list:
        if not i == i in used_chars:
            used_chars[i] = 1
        else:
            used_chars[i] += 1

    for k, v in used_chars.items():
        if v == 1:
            norep_chars.append(k)

    count = ns['len'] - len(norep_chars)
    ns['rept'] = count

    score = 0
    scores['rept'] = score


def pwd_cons_upcase():
    count = 0
    pos = 1

    while pos < ns['len']:
        if pwd_list[pos - 1].isupper() and pwd_list[pos].isupper():
            count += 1
            pos += 1
        else:
            pos += 1
    ns['upc_cons'] = count

    score = ns['upc_cons'] * 2
    scores['upc_cons'] = score


def pwd_cons_lowcase():
    count = 0
    pos = 1

    while pos < ns['len']:
        if pwd_list[pos - 1].islower() and pwd_list[pos].islower():
            count += 1
            pos += 1
        else:
            pos += 1
    ns['lowc_cons'] = count

    score = ns['lowc_cons'] * 2
    scores['lowc_cons'] = score


def pwd_cons_numbers():
    count = 0
    pos = 1

    while pos < ns['len']:
        if pwd_list[pos - 1].isdigit() and pwd_list[pos].isdigit():
            count += 1
            pos += 1
        else:
            pos += 1
    ns['nums_cons'] = count

    score = ns['nums_cons'] * 2
    scores['nums_cons'] = score


def pwd_cons_symbols():
    count = 0
    pos = 1

    while pos < ns['len']:
        if pwd_list[pos - 1].isdigit() and pwd_list[pos].isdigit():
            count += 1
            pos += 1
        else:
            pos += 1
    ns['syms_cons'] = count

    score = ns['syms_cons'] * 2
    scores['syms_cons'] = score


def pwd_entropy():
    score = 0
    ent_sel = {
        'enum': 1 if ns['nums'] > 0 and ns['upc'] == 0 and ns['lowc'] == 0
                     and ns['syms'] == 0 else 0,
        'elet': 1 if ns['nums'] == 0 and ns['upc'] > 0 and ns['lowc'] > 0
                     and ns['syms'] == 0 else 0,
        'eupc': 1 if ns['nums'] == 0 and ns['upc'] > 0 and ns['lowc'] == 0
                     and ns['syms'] == 0 else 0,
        'elowc': 1 if ns['nums'] == 0 and ns['upc'] == 0 and ns['lowc'] > 0
                     and ns['syms'] == 0 else 0,
        'esym': 1 if ns['nums'] == 0 and ns['upc'] == 0 and ns['lowc'] == 0
                     and ns['syms'] > 0 else 0,
        'eupcnum': 1 if ns['nums'] > 0 and ns['upc'] > 0 and ns['lowc'] == 0
                     and ns['syms'] == 0 else 0,
        'elowcnum': 1 if ns['nums'] > 0 and ns['upc'] == 0 and ns['lowc'] > 0
                     and ns['syms'] == 0 else 0,
        'enumsym': 1 if ns['nums'] > 0 and ns['upc'] == 0 and ns['lowc'] == 0
                     and ns['syms'] > 0 else 0,
        'eupcnumsym': 1 if ns['nums'] > 0 and ns['upc'] > 0 and ns['lowc'] == 0
                     and ns['syms'] > 0 else 0,
        'elowcnumsym': 1 if ns['nums'] > 0 and ns['upc'] == 0
                     and ns['lowc'] > 0 and ns['syms'] > 0 else 0,
        'eall': 1 if ns['nums'] > 0 and ns['upc'] > 0 and ns['lowc'] > 0
                     and ns['syms'] > 0 else 0
    }
    ent_calc = {
        'enum': math.log(10, 2),
        'elet': math.log(52, 2),
        'eupc': math.log(26, 2),
        'elowc': math.log(26, 2),
        'esym': math.log(33, 2),
        'eupcnum': math.log(36, 2),
        'elowcnum': math.log(36, 2),
        'enumsym': math.log(43, 2),
        'eupcnumsym': math.log(69, 2),
        'elowcnumsym': math.log(69, 2),
        'eall': math.log(95, 2)
    }
    for k, v in ent_sel.items():
        if v == 1:
            score = ent_calc[k] * ns['len']

    entropy['bits'] = score


# ------------------------------------------------------------------------------
# -------------------------- PROGRAM FUNCTIONS ---------------------------------
# ------------------------------------------------------------------------------


def val_pwd_ascii():

    for i in password:
        if ord(i) in range(32, 127):
            continue
        else:
            print('"{0}" is not allowed character.\n'
                  'Please only use ASCII characters.\n'.format(i))
            input('Press ENTER to continue ...')
            main()


def get_score():
    pwd_as_list()
    pwd_length()
    pwd_upcase()
    pwd_lowcase()
    pwd_numbers()
    pwd_symbols()
    pwd_mid_nr_or_sym()
    pwd_requirements()
    pwd_only_letters()
    pwd_only_numbers()
    pwd_rept_chars()
    pwd_cons_upcase()
    pwd_cons_lowcase()
    pwd_cons_numbers()
    pwd_cons_symbols()
    pwd_entropy()


def print_results():

    print('\n'
          'SCORE:      {0}\n'
          'COMPLEXITY: {1}\n\n'
          .format(pwd_score, pwd_complex))
    next = input('Press ENTER to continue\n'
                 'or\n'
                 'Type "X" to get details: ')

    if next == '':
        restart()
    elif next in ('X', 'x'):
        clear_screen()
        print_details()
    else:
        clear_screen()
        print_results()


def restart():
    clear_screen()
    print('\n'
          'Do you want to try again?\n'
          '   hit ENTER to CONTINUE\n'
          '   type NO or EXIT to QUIT the program\n')
    next = input('... waiting for your input: ')

    if next == '':
        main()
    elif next in ('n', 'no', 'not', 'ng', 'stop', 'quit', 'exit', '0',
                  'false', 'N', 'NO', 'NOT', 'NG', 'STOP', 'QUIT', 'EXIT', '0',
                  'FALSE'):
        clear_screen()
        print('\nThank you!')
    else:
        clear_screen()
        print('\n'
              'Press ENTER or type NO or EXIT\n\n\n')
        restart()


def print_details():
    """Print details about the password"""

    print('\n'
          'SCORE:      {0}\n'
          'COMPLEXITY: {1}\n'
          .format(pwd_score, pwd_complex))

    print('Password as list: {0}\n'.format(pwd_list))
    print('ns calculations: {0}\n'.format(ns))
    print('Scores calculations: {0}\n'.format(scores))
    print('Entropy: {0}\n'.format(entropy))

    # store string lengths for table
    plength = {
        'counts': 0,
        'scores': 0,
        'heading': 0
    }
    # loop value dicts to get lengths for table
    for k, v in ns.items():
        if len(str(v)) > plength['counts']:
            plength['counts'] = len(str(v))
    for k, v in scores.items():
        if len(str(v)) > plength['scores']:
            plength['scores'] = len(str(v))
    for k, v in stext.items():
        if len(v) > plength['heading']:
            plength['heading'] = len(v)

    # print table heading
    # t00, t11, t22 calculate indentation
    t00 = int(((plength['heading'] + 2 - 6) / 2)) * ' '
    t11 = int(((plength['counts'] + 1) / 2)) * ' '
    t22 = int(((plength['scores'] + 1) / 2)) * ' '
    print('{0}Metric{0}{1}Count{1}{2}Bonus'.format(t00, t11, t22))

    # print table content
    for k, v in stext.items():
        # get description
        t0 = stext[k]
        # indent count
        t1 = (plength['heading'] + plength['counts'] - len(stext[k]) - len(
            str(ns[k])) + 5) * ' '
        # get count
        t2 = ns[k]
        # indent score
        t3 = (plength['scores'] - len(str(scores[k])) + 5) * ' '
        # get score
        t4 = scores[k]
        print('{0}{1}{2}{3}{4}'.format(t0, t1, t2, t3, t4))


def main():
    set_window_size(win_console_width, win_console_height)
    clear_screen()

    global password
    password = str(input('\nType in your password : '))
    # password = ' A1b22CC 333ddd4 '
    print()

    val_pwd_ascii()

    get_score()

    print_results()


# ------------------------------------------------------------------------------
# ------------------------------- VARIABLES ------------------------------------
# ------------------------------------------------------------------------------


"""Global Variables

password: to store the password string
pwd_list: to store password as list by character
ns: to store .... etc"""
password = ''
pwd_list = []
ns = {
    'len': 0,
    'upc': 0,
    'lowc': 0,
    'nums': 0,
    'syms': 0,
    'mid': 0,
    'reqr': 0,
    'let_only': 0,
    'num_only': 0,
    'rept': 0,
    'upc_cons': 0,
    'lowc_cons': 0,
    'nums_cons': 0,
    'syms_cons': 0
}
scores = {
    'len': 0,
    'upc': 0,
    'lowc': 0,
    'nums': 0,
    'syms': 0,
    'mid': 0,
    'reqr': 0,
    'let_only': 0,
    'num_only': 0,
    'rept': 0,
    'upc_cons': 0,
    'lowc_cons': 0,
    'nums_cons': 0,
    'syms_cons': 0,
}
stext = {
    'len': 'Number of Characters',
    'upc': 'Uppercase Letters',
    'lowc': 'Lowercase Letters',
    'nums': 'Numbers',
    'syms': 'Symbols',
    'mid': 'Middle Numbers or Symbols',
    'reqr': 'Requirements',
    'let_only': 'Letters Only',
    'num_only': 'Numbers Only',
    'rept': 'Repeat Characters (Case Insensitive)',
    'upc_cons': 'Consecutive Uppercase Letters',
    'lowc_cons': 'Consecutive Lowercase Letters',
    'nums_cons': 'Consecutive Numbers',
    'syms_cons': 'Consecutive Symbols',
}
entropy = {'bits': 0, 'score': 0}
pwd_score = 0
pwd_complex = ''

# ------------------------------------------------------------------------------
# ------------------------------- RUN PROGRAM ----------------------------------
# ------------------------------------------------------------------------------


main()
