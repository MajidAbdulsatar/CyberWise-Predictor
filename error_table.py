import pandas as pd

def calculate_errors(row):
    row['impactScore_percentage_error'] = abs(row['impactScore'] - row['p_impactScore']) / row['impactScore'] * 100
    row['exploitabilityScore_percentage_error'] = abs(row['exploitabilityScore'] - row['p_exploitabilityScore']) / row['exploitabilityScore'] * 100
    row['baseScore_percentage_error'] = abs(row['baseScore'] - row['p_baseScore']) / row['baseScore'] * 100

    row['impactScore_bias'] = (row['impactScore'] - row['p_impactScore'])
    row['exploitabilityScore_bias'] = (row['exploitabilityScore'] - row['p_exploitabilityScore'])
    row['baseScore_bias'] = (row['baseScore'] - row['p_baseScore'])

    return row

def calc_error(file_name):
    # Read the CSV file
    df = pd.read_csv(file_name)

    # Calculate both percentage errors and bias for the three score columns
    error_df = df.apply(calculate_errors, axis=1)

    # Group by unique image and calculate the mean errors for each image
    grouped_error_df = error_df.groupby('image')[[
        'impactScore_percentage_error', 'exploitabilityScore_percentage_error', 'baseScore_percentage_error',
        'impactScore_bias', 'exploitabilityScore_bias', 'baseScore_bias'
    ]].mean().reset_index()

    # Save the results to table.csv
    grouped_error_df.to_csv('table.csv', index=False)

    print('Results saved to table.csv')
